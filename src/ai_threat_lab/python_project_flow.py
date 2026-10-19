"""Static links between selected flat root Python modules, without import execution."""

import ast
import re

from .models import ValidationError
from .python_flow import EMPTY, Flow, Value

MAX_INPUT_FILES = 100
MAX_FILES = 20
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
OFFSET = 1000000  # More than the maximum possible source lines in a selected file.
NOTICE = (
    "Project flow: engine python-root-modules-1.0; flat root .py modules, "
    "at most 20 files/2 MiB; "
    "static absolute local imports, no package/src/relative/dynamic import resolution, "
    "installation, execution, sys.path/runtime binding or exploitability validation."
)


class ProjectFlow(Flow):
    def __init__(self, trees, local_names):
        super().__init__()
        self.trees = trees
        self.local_names = local_names
        self.modules = {}
        self.loading = set()
        self.call_targets = {}

    def module_bindings(self, name):
        if name not in self.trees:
            self.note("selected local module unavailable; import binding unchecked.")
            return {}
        if name in self.loading:
            self.note("cyclic project imports unresolved; partial bindings retained.")
            return {}
        if name in self.modules:
            return self.modules[name]
        self.loading.add(name)
        previous = self.in_function, self.trace, self.returns
        self.in_function, self.trace, self.returns = 0, [], []
        env = {}
        try:
            normal = self.block(self.trees[name].body, env)
            if not normal:
                env.clear()
                self.note("module pass did not complete; exported bindings unchecked.")
            self.modules[name] = env
            return env
        finally:
            self.in_function, self.trace, self.returns = previous
            self.loading.remove(name)

    def exported_function(self, module, name):
        value = self.module_bindings(module).get(name, EMPTY)
        if not value.function:
            self.note("local module export is not a definite function; binding unchecked.")
            return EMPTY
        return value

    def import_bindings(self, statement, env):
        if isinstance(statement, ast.Import) and any(
            item.name in self.local_names for item in statement.names
        ):
            for item in statement.names:
                if item.name in self.local_names:
                    self.module_bindings(item.name)
                    env[item.asname or item.name] = Value(module=item.name)
                else:
                    env[item.asname or item.name.split(".")[0]] = Value(
                        symbol=item.name if item.asname else item.name.split(".")[0]
                    )
            return True
        if (
            isinstance(statement, ast.ImportFrom)
            and statement.level == 0
            and statement.module in self.local_names
        ):
            if any(item.name == "*" for item in statement.names):
                env.clear()
                self.note("local star imports unresolved; tracking reset.")
            else:
                for item in statement.names:
                    env[item.asname or item.name] = self.exported_function(
                        statement.module, item.name
                    )
            return True
        return False

    def attribute(self, parent, node):
        if parent.module:
            return self.exported_function(parent.module, node.attr)
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
    local_names = {
        name[:-3]
        for name in names | set(unavailable)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,251}\.py", name) and name != "__init__.py"
    }
    total, attempts = 0, 0
    for entry in sorted(sources, key=lambda item: item[0]):
        name, source = entry
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,251}\.py", name) or name == "__init__.py":
            notices.append("Project flow: non-flat/unsupported module paths remain unchecked.")
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
    trees = {name[:-3]: tree for name, tree in selected}
    flow = ProjectFlow(trees, local_names)
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
        f"Project flow: inspected {len(selected)} root modules from {attempts} attempts "
        f"({total} UTF-8 bytes)."
    )
    return tuple(findings), tuple(dict.fromkeys(notices))
