"""Static links between selected regular Python modules, without import execution."""

import ast

from . import python_flow as flow_limits
from .models import ValidationError
from .python_flow import EMPTY, Flow, Value
from .python_import_calls import literal_import_target
from .python_module_index import module_index

MAX_INPUT_FILES = 100
MAX_FILES = 20
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
OFFSET = 1000000  # More than the maximum possible source lines in a selected file.
NOTICE = (
    "Project flow: engine python-project-modules-1.4; root/src modules and selected "
    "regular packages, at most 20 files/2 MiB; static absolute/relative local imports, "
    "literal importlib.import_module calls only; no namespace/computed dynamic imports, "
    "installation, execution, sys.path/runtime binding "
    "or exploitability validation."
)


class ProjectFlow(Flow):
    def __init__(self, trees, local_names, specs, module_order):
        super().__init__()
        self.trees = trees
        self.local_names = local_names
        self.specs = specs
        self.module_order = module_order
        self.current_module = ""
        self.completed = set()
        self.in_progress = {}
        self.modules = {}
        self.loading = set()
        self.call_targets = {}
        self.uncertain_namespaces = set()
        self.initializer_children = {}
        self.namespace_depths = {}

    def block(self, body, env, *, depth=0, scope=True):
        name = self.current_module
        previous = self.in_progress.get(name)
        previous_depth = self.namespace_depths.get(name, 0)
        module_scope = not self.in_function and name in self.loading
        if module_scope:
            self.in_progress[name] = env
            self.namespace_depths[name] = depth
        try:
            return super().block(body, env, depth=depth, scope=scope)
        finally:
            if module_scope:
                self.in_progress[name] = previous
                self.namespace_depths[name] = previous_depth

    def reset_bindings(self, env, notice):
        super().reset_bindings(env, notice)
        if not self.in_function:
            self.uncertain_namespaces.add(self.current_module)

    def module_bindings(self, name):
        if name not in self.trees:
            self.note("selected local module unavailable; import binding unchecked.")
            return {}
        if name in self.loading:
            self.note("cyclic project imports unresolved; partial bindings retained.")
            return {}
        parts = name.split(".")
        for size in range(1, len(parts)):
            parent = ".".join(parts[:size])
            if (
                parent not in self.specs
                or not self.specs[parent].package
                or parent not in self.trees
            ):
                self.note("package parent unavailable/ambiguous; child binding unchecked.")
                return {}
            if parent not in self.loading:
                self.module_bindings(parent)
                if parent not in self.completed:
                    self.note("package initializer pass incomplete; child binding unchecked.")
                    return {}
        if name in self.modules:
            return self.modules[name]
        self.loading.add(name)
        previous = self.in_function, self.trace, self.returns, self.current_module
        self.in_function, self.trace, self.returns = 0, [], []
        self.current_module = name
        env = {}
        self.in_progress[name] = env
        try:
            normal = self.block(self.trees[name].body, env)
            if not normal:
                env.clear()
                self.note("module pass did not complete; exported bindings unchecked.")
            else:
                self.completed.add(name)
            self.modules[name] = env
            return env
        finally:
            self.in_function, self.trace, self.returns, self.current_module = previous
            self.loading.remove(name)
            self.in_progress.pop(name, None)

    def exported_binding(self, module, name, *, load_child=False):
        if module == self.current_module and module in self.loading:
            bindings = self.in_progress[module]
        else:
            bindings = self.module_bindings(module)
        value = bindings.get(name, EMPTY)
        child = f"{module}.{name}"
        if child in self.local_names:
            if value.function or value.module:
                if value.module == child:
                    return value
                self.note("ambiguous function/module export; binding unchecked.")
                return EMPTY
            if name in bindings:
                self.note("package attribute shadows collected child; binding unchecked.")
                return EMPTY
            if not load_child:
                self.note("collected child not established by an import; attribute unchecked.")
                return EMPTY
            spec = self.specs.get(module)
            if module in self.uncertain_namespaces or not spec or not spec.package:
                self.note("package namespace uncertain; absent child binding unchecked.")
                return EMPTY
            self.module_bindings(child)
            if child not in self.completed:
                self.note("package child unavailable/incomplete; binding unchecked.")
                return EMPTY
            self.record_initializer_import(child)
            return Value(module=child)
        if not (value.function or value.module):
            self.note("local module export is not a definite function; binding unchecked.")
            return EMPTY
        return value

    def local_import(self, name):
        return bool(name) and name.split(".")[0] in self.local_names

    def relative_target(self, statement):
        spec = self.specs.get(self.current_module)
        package = (
            self.current_module if spec and spec.package else self.current_module.rpartition(".")[0]
        )
        parts = package.split(".") if package else []
        if not parts or statement.level > len(parts):
            return ""
        base = ".".join(parts[: len(parts) - statement.level + 1])
        return base + ("." + statement.module if statement.module else "")

    def record_initializer_import(self, target):
        if self.in_function or target not in self.completed:
            return
        parts = target.split(".")
        for size in range(1, len(parts)):
            parent, child = ".".join(parts[:size]), ".".join(parts[: size + 1])
            spec = self.specs.get(parent)
            if parent not in self.loading or not spec or not spec.package:
                continue
            if self.namespace_depths.get(parent, 0):
                self.uncertain_namespaces.add(parent)
                self.note(
                    "nested initializer import effects unchecked; package namespace uncertain."
                )
                continue
            loaded = self.initializer_children.setdefault(parent, set())
            if child in self.completed and child not in loaded:
                self.in_progress[parent][parts[size]] = Value(
                    module=child, loaded_children=frozenset({target})
                )
                loaded.add(child)

    def imported_path_available(self, target):
        parts = target.split(".")
        for size in range(1, len(parts)):
            parent, child = ".".join(parts[:size]), ".".join(parts[: size + 1])
            bindings = self.in_progress.get(parent, self.modules.get(parent, {}))
            if parent in self.uncertain_namespaces or (
                child in self.initializer_children.get(parent, ())
                and bindings.get(parts[size], EMPTY).module != child
            ):
                self.note("cached/rebound or uncertain package child; import binding unchecked.")
                return False
        return True

    def scoped_child_bindings(self, target, child, env):
        known = []
        for value in env.values():
            self.steps += 1
            if self.steps > flow_limits.MAX_STEPS:
                self.note("scoped import lookup step limit reached; extra bindings unchecked.")
                break
            if (
                value.module == target
                and any(
                    path == child or path.startswith(child + ".") for path in value.loaded_children
                )
            ) or (value.module == child and child in value.loaded_children):
                known.append(value)
        return known

    def import_bindings(self, statement, env):
        if isinstance(statement, ast.Import) and any(
            self.local_import(item.name) for item in statement.names
        ):
            for item in statement.names:
                if self.local_import(item.name):
                    self.module_bindings(item.name)
                    bound = item.name if item.asname else item.name.split(".")[0]
                    self.record_initializer_import(item.name)
                    available = self.imported_path_available(item.name)
                    previous = env.get(item.asname or bound, EMPTY)
                    loaded = previous.loaded_children if previous.module == bound else frozenset()
                    if item.asname and not available:
                        env[item.asname] = EMPTY
                    else:
                        env[item.asname or bound] = Value(
                            module=bound,
                            loaded_children=loaded
                            | ({item.name} if available and item.name in self.completed else set()),
                        )
                else:
                    env[item.asname or item.name.split(".")[0]] = Value(
                        symbol=item.name if item.asname else item.name.split(".")[0]
                    )
            return True
        if isinstance(statement, ast.ImportFrom):
            target = self.relative_target(statement) if statement.level else statement.module
            if not statement.level and not self.local_import(target):
                return False
            if any(item.name == "*" for item in statement.names):
                self.reset_bindings(env, "local star imports unresolved; tracking reset.")
            elif not target or not self.local_import(target):
                for item in statement.names:
                    env[item.asname or item.name] = EMPTY
                self.note("relative local import unresolved; binding unchecked.")
            else:
                for item in statement.names:
                    child = f"{target}.{item.name}"
                    known = self.scoped_child_bindings(target, child, env)
                    if known and child in self.completed and self.imported_path_available(child):
                        value = Value(
                            module=child,
                            loaded_children=frozenset.union(
                                *(value.loaded_children for value in known)
                            ),
                        )
                    else:
                        value = self.exported_binding(target, item.name, load_child=True)
                    env[item.asname or item.name] = value
                self.record_initializer_import(target)
            return True
        return False

    def analyze_function(self, function, local, *, call_line=None):
        previous = self.current_module
        self.current_module = self.module_order[function.lineno // OFFSET]
        try:
            return super().analyze_function(function, local, call_line=call_line)
        finally:
            self.current_module = previous

    def call_result(self, function, node):
        if function.symbol != "importlib.import_module":
            return None
        target = literal_import_target(node)
        if not target or target not in self.local_names:
            self.note("importlib call has unsupported arguments or uncollected target; unchecked.")
            return EMPTY
        self.module_bindings(target)
        if target not in self.completed:
            self.note("importlib target pass unavailable/incomplete; result unchecked.")
            return EMPTY
        self.record_initializer_import(target)
        return Value(
            module=target, loaded_children=frozenset({target}), call_sites=function.call_sites
        )

    def attribute(self, parent, node):
        if parent.module:
            child = f"{parent.module}.{node.attr}"
            if any(
                path == child or path.startswith(child + ".") for path in parent.loaded_children
            ):
                self.module_bindings(child)
                if child in self.completed:
                    return Value(module=child, loaded_children=parent.loaded_children)
                self.note("explicitly imported child unavailable/incomplete; attribute unchecked.")
                return EMPTY
            return self.exported_binding(parent.module, node.attr)
        return super().attribute(parent, node)

    def invoke(self, identity, call, args, kwargs):
        previous_calls = self.calls
        value = super().invoke(identity, call, args, kwargs)
        if self.calls > previous_calls:
            definition = self.functions[identity][0].lineno
            self.call_targets.setdefault(call.lineno, set()).add(definition)
        return value


def project_flows(sources, *, unavailable=()):
    """Assess already-collected text. Filenames are labels, never opened or imported."""
    from .assessment import AssessmentFinding

    if not isinstance(sources, (list, tuple)) or len(sources) > MAX_INPUT_FILES:
        raise ValidationError("Project flow requires at most 100 collected Python sources")
    if (
        not isinstance(unavailable, (list, tuple))
        or any(not isinstance(name, str) for name in unavailable)
        or len(sources) + len(unavailable) > MAX_INPUT_FILES
    ):
        raise ValidationError("Invalid unavailable project module labels")
    names, selected, notices = set(), [], [NOTICE]
    for entry in sources:
        if (
            not isinstance(entry, (list, tuple))
            or len(entry) != 2
            or not isinstance(entry[0], str)
            or not isinstance(entry[1], str)
            or entry[0] in names
        ):
            raise ValidationError("Invalid or duplicate project source input")
        names.add(entry[0])
    specs, local_names, index_notices = module_index(names | set(unavailable))
    notices.extend(index_notices)
    by_path = {spec.path: spec for spec in specs.values()}
    total, attempts = 0, 0
    for entry in sorted(sources, key=lambda item: item[0]):
        name, source = entry
        if name not in by_path:
            continue
        try:
            size = len(source.encode("utf-8"))
        except UnicodeError:
            notices.append("Project flow: invalid source encoding skipped.")
            continue
        if size > MAX_FILE_BYTES:
            notices.append("Project flow: oversized module skipped.")
            continue
        if attempts >= MAX_FILES or total + size > MAX_TOTAL_BYTES:
            notices.append(
                "Project flow: file/total-byte limit reached; additional modules unchecked."
            )
            continue
        attempts += 1
        total += size
        try:
            tree = ast.parse(source, filename=name)
        except (SyntaxError, ValueError, RecursionError):
            notices.append(f"Project flow: {name}: unparsable module skipped.")
            continue
        ast.increment_lineno(tree, len(selected) * OFFSET)
        selected.append((name, tree))
    trees = {by_path[name].name: tree for name, tree in selected}
    flow = ProjectFlow(trees, local_names, specs, [by_path[name].name for name, _ in selected])
    for name in sorted(trees):
        flow.module_bindings(name)

    def location(encoded):
        index, line = divmod(encoded, OFFSET)
        return f"{selected[index][0]}:{line}"

    findings = []
    for rule, node, origins, calls in flow.observations:
        definitions = {d for call in calls for d in flow.call_targets.get(call, ())}
        module = node.lineno // OFFSET
        if not any(line // OFFSET != module for line in (*origins, *calls, *definitions)):
            continue  # Existing per-file routes already report these observations.
        if len(definitions) > 8:
            flow.note("helper-definition evidence limit reached; at most eight locations retained.")
        definitions = sorted(definitions, key=lambda line: (line // OFFSET == module, line))[:8]
        shell = rule == "PY013"
        evidence = (
            f"{location(node.lineno)}:{node.col_offset + 1}: cross-file candidate; "
            "HTTP source(s): "
            + ", ".join(map(location, origins))
            + "; call site(s): "
            + (", ".join(map(location, calls)) or "none recorded")
            + "; helper definition(s): "
            + (", ".join(map(location, definitions)) or "none recorded")
            + ". Possible static dependency; runtime bindings/path feasibility unverified."
        )
        findings.append(
            AssessmentFinding(
                rule,
                "candidate",
                evidence,
                "Avoid shell interpretation and review input-to-command paths."
                if shell
                else "Keep query structure separate from input; use SQLite parameter binding.",
            )
        )
    notices.extend(sorted(flow.notices))
    notices.append(
        f"Project flow: inspected {len(selected)} modules from {attempts} attempts "
        f"({total} UTF-8 bytes)."
    )
    return tuple(findings), tuple(dict.fromkeys(notices))
