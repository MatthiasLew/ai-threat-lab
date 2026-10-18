"""Bounded straight-line Flask-to-shell/SQLite candidate discovery, without execution."""

import ast
from dataclasses import dataclass

NOTICE = (
    "Flow coverage: selected Flask sources and shell/SQLite sinks, straight-line local "
    "assignments only; no interprocedural, branch, heap, sanitizer, runtime-binding "
    "or exploitability validation."
)
MAX_STEPS = 20000
MAX_DEPTH = 64
MAX_SCOPES = 100
MAX_FINDINGS = 200
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
}


@dataclass(frozen=True)
class Value:
    symbol: str = ""
    origins: frozenset[int] = frozenset()
    database: bool = False


EMPTY = Value()


class Flow:
    def __init__(self):
        self.steps = 0
        self.scopes = 0
        self.observations = []
        self.notices = set()

    def note(self, text):
        self.notices.add("Flow coverage: " + text)

    def merge(self, values):
        origins = set().union(*(v.origins for v in values))
        if len(origins) > 8:
            self.note("source-origin limit reached; only the first eight line numbers retained.")
        return Value(origins=frozenset(sorted(origins)[:8]))

    def record(self, rule, node, value):
        if not value.origins:
            return
        if len(self.observations) >= MAX_FINDINGS:
            self.note("finding limit reached; additional flow observations omitted.")
            return
        self.observations.append((rule, node, tuple(sorted(value.origins))))

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
            return Value(symbol=symbol, origins=origins)
        if isinstance(node, ast.Subscript):
            value = evaluate(node.value)
            evaluate(node.slice)
            return Value(origins=value.origins)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self.merge([evaluate(node.left), evaluate(node.right)])
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
            )
            if method
            else evaluate(node.func)
        )
        args = [evaluate(item) for item in node.args]
        kwargs = {item.arg: evaluate(item.value) for item in node.keywords}
        name = function.symbol
        if name in ("flask.request.get_json", "flask.request.get_data"):
            return Value(origins=frozenset({node.lineno}))
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

    def block(self, body, env):
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
                local = {
                    key: value
                    for key, value in env.items()
                    if value.symbol and not value.origins and not value.database
                }
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
                env[statement.name] = EMPTY
                self.block(statement.body, local)
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
                self.expr(
                    statement.value if isinstance(statement, ast.Return) else statement.exc, env
                )
                return
            elif isinstance(statement, ast.Delete):
                for target in statement.targets:
                    self.bind(target, EMPTY, env)
            elif not isinstance(statement, ast.Pass):
                # Branches, loops, with/try, classes and global/nonlocal effects need a CFG.
                env.clear()
                self.note("control flow/classes/scope effects skipped; tracking reset at barrier.")


def discover_flows(tree):
    flow = Flow()
    flow.block(tree.body, {})
    return flow.observations, (NOTICE, *sorted(flow.notices))
