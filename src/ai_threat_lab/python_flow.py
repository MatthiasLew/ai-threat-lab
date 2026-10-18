"""Bounded local Flask-to-shell/SQLite candidate discovery, without execution."""

import ast
from dataclasses import dataclass

from .python_call_binding import bind_arguments

NOTICE = (
    "Flow coverage: selected Flask sources and shell/SQLite sinks, local assignments, "
    "branch joins, one-pass loops and bounded same-file calls; no cross-file, path-feasibility, "
    "heap, sanitizer, runtime-binding or exploitability validation; "
    "callee exception/effect behavior is not propagated."
)
MAX_STEPS = 20000
MAX_DEPTH = 64
MAX_BLOCK_DEPTH = 32
MAX_SCOPES = 100
MAX_FINDINGS = 200
MAX_FUNCTIONS = 100
MAX_CALLS = 100
MAX_CALL_DEPTH = 4
SOURCE_FIELDS = {"args", "form", "values", "cookies", "headers", "json", "data", "query_string"}
SHELL_CALLS = {"os.system", "os.popen"}
SUBPROCESS_CALLS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
}
TRANSFORMS = {
    "format",
    "join",
    "strip",
    "lstrip",
    "rstrip",
    "lower",
    "upper",
    "replace",
    "encode",
    "decode",
    "split",
    "rsplit",
    "splitlines",
}


@dataclass(frozen=True)
class Value:
    symbol: str = ""
    origins: frozenset[int] = frozenset()
    database: bool = False
    function: int = 0
    call_sites: frozenset[int] = frozenset()


EMPTY = Value()


class Flow:
    def __init__(self):
        self.steps = 0
        self.scopes = 0
        self.observations = []
        self.notices = set()
        self.functions = {}
        self.calls = 0
        self.in_function = 0
        self.active = set()
        self.trace = []
        self.returns = []
        self.observation_indexes = {}

    def note(self, text):
        self.notices.add("Flow coverage: " + text)

    def merge(self, values):
        origins = set().union(*(v.origins for v in values))
        if len(origins) > 8:
            self.note("source-origin limit reached; only the first eight line numbers retained.")
        call_sites = set().union(*(v.call_sites for v in values))
        if len(call_sites) > 8:
            self.note("call-site evidence limit reached; first eight lines retained.")
        return Value(
            origins=frozenset(sorted(origins)[:8]), call_sites=frozenset(sorted(call_sites)[:8])
        )

    def join_value(self, values):
        symbols = {value.symbol for value in values}
        database = all(value.database for value in values)
        functions = {value.function for value in values}
        if (
            (len(functions) > 1 and any(functions))
            or (len(symbols) > 1 and any(symbols))
            or (any(value.database for value in values) and not database)
        ):
            self.note("join lost ambiguous API/object bindings; some flows unchecked.")
        merged = self.merge(values)
        return Value(
            symbol=values[0].symbol if len(symbols) == 1 else "",
            origins=merged.origins,
            call_sites=merged.call_sites,
            database=database,
            function=values[0].function if len(functions) == 1 else 0,
        )

    def join_env(self, states):
        return {
            key: self.join_value([state.get(key, EMPTY) for state in states])
            for key in set().union(*(state.keys() for state in states))
        }

    @staticmethod
    def literal_bool(node):
        return node.value if isinstance(node, ast.Constant) and type(node.value) is bool else None

    def conditional(self, statement, env, depth):
        self.expr(statement.test, env)
        condition = self.literal_bool(statement.test)
        branches = (
            [statement.body]
            if condition is True
            else [statement.orelse]
            if condition is False
            else [statement.body, statement.orelse]
        )
        states = []
        for branch in branches:
            state = dict(env)
            if self.block(branch, state, depth=depth + 1, scope=False):
                states.append(state)
        if not states:
            return False
        env.clear()
        env.update(self.join_env(states))
        return True

    def loop(self, statement, env, depth):
        self.note("one-pass loops only; loop-carried dependencies/convergence unchecked.")
        if any(isinstance(node, (ast.Break, ast.Continue)) for node in ast.walk(statement)):
            env.clear()
            self.note("loop with break/continue skipped; tracking reset at barrier.")
            return True
        is_while = isinstance(statement, ast.While)
        condition = self.literal_bool(statement.test) if is_while else None
        value = self.expr(statement.test if is_while else statement.iter, env)
        initial, iteration = dict(env), dict(env)
        if not is_while:
            self.bind(
                statement.target,
                Value(origins=value.origins, call_sites=value.call_sites),
                iteration,
            )
        states = [initial]
        if condition is not False:
            reaches_end = self.block(statement.body, iteration, depth=depth + 1, scope=False)
            if is_while and condition is True:
                # No break is supported: literal True cannot reach its else or successor.
                return False
            if reaches_end:
                states.append(iteration)
        env.clear()
        env.update(self.join_env(states))
        return self.block(statement.orelse, env, depth=depth + 1, scope=False)

    def record(self, rule, node, value):
        if not value.origins:
            return
        key = rule, node.lineno, node.col_offset
        call_lines = {line for _, line in self.trace} | set(value.call_sites)
        origins = set(value.origins)
        if key in self.observation_indexes:
            index = self.observation_indexes[key]
            previous = self.observations[index]
            origins.update(previous[2])
            call_lines.update(previous[3])
        else:
            if len(self.observations) >= MAX_FINDINGS:
                self.note("finding limit reached; additional flow observations omitted.")
                return
            index = len(self.observations)
            self.observation_indexes[key] = index
            self.observations.append(None)
        if len(origins) > 8 or len(call_lines) > 8:
            self.note("source/call-site evidence limit reached; first eight lines retained.")
        self.observations[index] = (
            rule,
            node,
            tuple(sorted(origins)[:8]),
            tuple(sorted(call_lines)[:8]),
        )

    @staticmethod
    def visible_bindings(env):
        return {
            key: value
            for key, value in env.items()
            if (value.symbol or value.function) and not value.origins and not value.database
        }

    def analyze_function(self, function, local, *, call_line=None):
        identity = id(function)
        previous_trace = self.trace
        if call_line is None:
            self.trace = []
        else:
            self.trace = [*self.trace, (identity, call_line)]
        self.active.add(identity)
        self.in_function += 1
        self.returns.append([])
        try:
            normal = self.block(function.body, local)
            values = self.returns[-1]
            if normal:
                values.append(EMPTY)
            if not values:
                self.note("callee termination/exception behavior not propagated to caller.")
                return EMPTY
            return self.join_value(values)
        finally:
            self.returns.pop()
            self.in_function -= 1
            self.active.discard(identity)
            self.trace = previous_trace

    def invoke(self, identity, call, args, kwargs):
        function, captured = self.functions[identity]
        if identity in self.active:
            self.note("recursive local call skipped; no recursive fixed point is computed.")
            return EMPTY
        if self.calls >= MAX_CALLS or len(self.trace) >= MAX_CALL_DEPTH:
            self.note("local call count/depth limit reached; additional calls unchecked.")
            return EMPTY
        bound = bind_arguments(function, call, args, kwargs, EMPTY)
        if bound is None:
            self.note("unsupported/invalid local signature or argument binding; call unchecked.")
            return EMPTY
        self.calls += 1
        local = dict(captured)
        local.update(bound)
        result = self.analyze_function(function, local, call_line=call.lineno)
        sites = result.call_sites | {call.lineno}
        if len(sites) > 8:
            self.note("call-site evidence limit reached; first eight lines retained.")
        return Value(
            symbol=result.symbol,
            origins=result.origins,
            database=result.database,
            function=result.function,
            call_sites=frozenset(sorted(sites)[:8]),
        )

    def expr(self, node, env, depth=0):
        if node is None:
            return EMPTY
        self.steps += 1
        if self.steps > MAX_STEPS or depth > MAX_DEPTH:
            self.note("expression step/depth limit reached; remaining expressions unchecked.")
            return EMPTY

        def evaluate(item):
            return self.expr(item, env, depth + 1)

        if isinstance(node, ast.Name):
            return env.get(node.id, EMPTY)
        if isinstance(node, ast.Constant):
            return EMPTY
        if isinstance(node, ast.Attribute):
            parent = evaluate(node.value)
            symbol = f"{parent.symbol}.{node.attr}" if parent.symbol else ""
            origins = parent.origins
            if parent.symbol == "flask.request" and node.attr in SOURCE_FIELDS:
                origins = frozenset({node.lineno})
            return Value(symbol=symbol, origins=origins, call_sites=parent.call_sites)
        if isinstance(node, ast.Subscript):
            value = evaluate(node.value)
            evaluate(node.slice)
            return Value(origins=value.origins, call_sites=value.call_sites)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self.merge([evaluate(node.left), evaluate(node.right)])
        if isinstance(node, ast.IfExp):
            evaluate(node.test)
            condition = self.literal_bool(node.test)
            if condition is not None:
                return evaluate(node.body if condition else node.orelse)
            return self.join_value([evaluate(node.body), evaluate(node.orelse)])
        if isinstance(node, ast.BoolOp):
            values = []
            for item in node.values:
                values.append(evaluate(item))
                literal = self.literal_bool(item)
                if (isinstance(node.op, ast.And) and literal is False) or (
                    isinstance(node.op, ast.Or) and literal is True
                ):
                    break
            return self.merge(values)
        if isinstance(node, ast.Compare):
            evaluate(node.left)
            for item in node.comparators:
                evaluate(item)
            return EMPTY
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            evaluate(node.operand)
            return EMPTY
        if isinstance(node, ast.JoinedStr):
            return self.merge([evaluate(item) for item in node.values])
        if isinstance(node, ast.FormattedValue):
            return evaluate(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self.merge([evaluate(item) for item in node.elts])
        if isinstance(node, ast.Dict):
            return self.merge([evaluate(item) for item in [*node.keys, *node.values]])
        if not isinstance(node, ast.Call):
            self.note("unsupported expression forms unchecked; their values are not propagated.")
            return EMPTY
        receiver = evaluate(node.func.value) if isinstance(node.func, ast.Attribute) else EMPTY
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        function = (
            Value(
                symbol=f"{receiver.symbol}.{method}" if receiver.symbol else "",
                origins=receiver.origins,
                call_sites=receiver.call_sites,
            )
            if method
            else evaluate(node.func)
        )
        args = [evaluate(item) for item in node.args]
        kwargs = {item.arg: evaluate(item.value) for item in node.keywords}
        name = function.symbol
        if function.function:
            return self.invoke(function.function, node, args, kwargs)
        if name in ("flask.request.get_json", "flask.request.get_data"):
            return Value(origins=frozenset({node.lineno}), call_sites=function.call_sites)
        if name in SHELL_CALLS or (
            name in SUBPROCESS_CALLS
            and any(
                item.arg == "shell"
                and isinstance(item.value, ast.Constant)
                and item.value.value is True
                for item in node.keywords
            )
        ):
            command = args[0] if args else kwargs.get("args", kwargs.get("command", EMPTY))
            self.record("PY013", node, command)
        if name == "sqlite3.connect":
            return Value(database=True)
        if receiver.database:
            if method == "cursor":
                return Value(database=True)
            if method in ("execute", "executemany", "executescript"):
                self.record("PY014", node, args[0] if args else kwargs.get("sql", EMPTY))
                return Value(database=True)
        # Only these explicit string/container operations retain input dependencies.
        if (method in TRANSFORMS or method in ("get", "getlist")) and receiver.origins:
            return self.merge([receiver, *args, *kwargs.values()])
        if method in ("format", "join"):
            return self.merge([receiver, *args, *kwargs.values()])
        if isinstance(node.func, ast.Name) and node.func.id == "str" and "str" not in env:
            return self.merge(args)
        if function.origins or any(v.origins for v in [*args, *kwargs.values()]):
            self.note("unknown call results are not propagated; wrappers/sanitizers unchecked.")
        return EMPTY

    def bind(self, target, value, env):
        if isinstance(target, ast.Name):
            env[target.id] = value
        else:
            for node in ast.walk(target):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                    env[node.id] = EMPTY
            self.note("destructuring/attribute/subscript writes are not modeled.")

    def block(self, body, env, *, depth=0, scope=True):
        if depth > MAX_BLOCK_DEPTH:
            env.clear()
            self.note("control-flow nesting limit reached; deeper blocks unchecked.")
            return True
        if scope:
            self.scopes += 1
        if self.scopes > MAX_SCOPES:
            self.note("scope limit reached; additional function bodies unchecked.")
            return
        for statement in body:
            self.steps += 1
            if self.steps > MAX_STEPS:
                self.note("expression step/depth limit reached; remaining expressions unchecked.")
                return
            if isinstance(statement, ast.Import):
                for item in statement.names:
                    env[item.asname or item.name.split(".")[0]] = Value(
                        symbol=item.name if item.asname else item.name.split(".")[0]
                    )
            elif isinstance(statement, ast.ImportFrom):
                if any(item.name == "*" for item in statement.names):
                    env.clear()
                    self.note("relative/star imports are not resolved.")
                elif statement.module and statement.level == 0:
                    for item in statement.names:
                        env[item.asname or item.name] = Value(
                            symbol=f"{statement.module}.{item.name}"
                        )
                else:
                    for item in statement.names:
                        env[item.asname or item.name] = EMPTY
                    self.note("relative/star imports are not resolved.")
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                local = self.visible_bindings(env)
                if not self.in_function and len(self.functions) < MAX_FUNCTIONS:
                    identity = id(statement)
                    env[statement.name] = Value(function=identity)
                    local[statement.name] = env[statement.name]
                    self.functions[identity] = statement, dict(local)
                else:
                    env[statement.name] = EMPTY
                    self.note("nested/function-table-limit definitions have no callable binding.")
                arguments = statement.args
                for arg in [
                    *arguments.posonlyargs,
                    *arguments.args,
                    *arguments.kwonlyargs,
                    arguments.vararg,
                    arguments.kwarg,
                ]:
                    if arg is not None:
                        local[arg.arg] = EMPTY
                self.analyze_function(statement, local)
            elif isinstance(statement, ast.If):
                if not self.conditional(statement, env, depth):
                    return False
            elif isinstance(statement, (ast.For, ast.While)):
                if not self.loop(statement, env, depth):
                    return False
            elif isinstance(statement, ast.Assign):
                value = self.expr(statement.value, env)
                for target in statement.targets:
                    self.bind(target, value, env)
            elif isinstance(statement, ast.AnnAssign):
                self.bind(statement.target, self.expr(statement.value, env), env)
            elif isinstance(statement, ast.AugAssign):
                value = self.expr(statement.value, env)
                if isinstance(statement.target, ast.Name) and isinstance(statement.op, ast.Add):
                    value = self.merge([env.get(statement.target.id, EMPTY), value])
                else:
                    value = EMPTY
                    self.note("unsupported augmented assignments unchecked.")
                self.bind(statement.target, value, env)
            elif isinstance(statement, ast.Expr):
                self.expr(statement.value, env)
            elif isinstance(statement, (ast.Return, ast.Raise)):
                value = self.expr(
                    statement.value if isinstance(statement, ast.Return) else statement.exc, env
                )
                if isinstance(statement, ast.Return) and self.returns:
                    self.returns[-1].append(value)
                return
            elif isinstance(statement, ast.Delete):
                for target in statement.targets:
                    self.bind(target, EMPTY, env)
            elif not isinstance(statement, ast.Pass):
                # Exceptions/context managers/classes and scope effects remain barriers.
                env.clear()
                self.note("control flow/classes/scope effects skipped; tracking reset at barrier.")

        return True


def discover_flows(tree):
    flow = Flow()
    flow.block(tree.body, {})
    return flow.observations, (NOTICE, *sorted(flow.notices))
