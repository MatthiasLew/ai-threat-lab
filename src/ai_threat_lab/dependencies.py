"""Static pinned dependency inventory and bounded OSV advisory lookups; no installs."""

import hashlib
import json
import math
import os
import re
import sqlite3
import time
import tomllib
from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

from .assessment import AssessmentFinding, AssessmentResult
from .contracts import _nonfinite, _pairs
from .dependency_paths import (
    MAX_TOTAL_BYTES,
    discover_manifests,
    linked,
    valid_source_path,
)
from .dependency_paths import (
    SUPPORTED as SUPPORTED,
)
from .dependency_paths import (
    is_manifest as is_manifest,
)
from .go_inventory import module_path, module_version, parse_go_sum
from .models import ValidationError
from .providers import ProviderError

MAX_BYTES = 2 * 1024 * 1024
MAX_PACKAGES = 500
NAME = {
    "Go": r"[A-Za-z0-9._~/-]{1,512}",
    "PyPI": r"[A-Za-z0-9][A-Za-z0-9._-]{0,213}",
    "npm": r"(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]{0,213}",
    "crates.io": r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}",
}
VERSION = r"[0-9][A-Za-z0-9.!+_-]{0,127}"
ADVISORY_ID = r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}"


def _crate_version(value):
    if not isinstance(value, str) or len(value) > 128:
        return False
    match = re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
        r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
        r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
        value,
    )
    return bool(match) and all(
        not (part.isdigit() and len(part) > 1 and part.startswith("0"))
        for part in (match[1] or "").split(".")
    )


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    sources: tuple[str, ...]

    def __post_init__(self):
        if (
            self.ecosystem not in NAME
            or not isinstance(self.name, str)
            or not re.fullmatch(NAME[self.ecosystem], self.name)
            or not isinstance(self.version, str)
            or (
                not (module_path(self.name) and module_version(self.version))
                if self.ecosystem == "Go"
                else not re.fullmatch(VERSION, self.version)
            )
        ):
            raise ValidationError("Dependency requires a supported name and exact version")

    def query(self):
        return {
            "package": {"ecosystem": self.ecosystem, "name": self.name},
            "version": self.version,
        }


def normalize(name, ecosystem):
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name


@dataclass(frozen=True)
class Inventory:
    target: str
    packages: tuple[Dependency, ...]
    not_checked: tuple[str, ...]

    def document(self):
        return {
            "schema_version": 1,
            "target": self.target,
            "packages": [asdict(p) for p in self.packages],
            "not_checked": self.not_checked,
        }


def inventory(path: Path, *, recursive=False) -> Inventory:
    path = Path(path)
    if type(recursive) is not bool:
        raise ValidationError("Recursive dependency selection must be boolean")
    if linked(path) or not path.exists():
        raise ValidationError("Dependency target must exist and must not be a symlink/junction")
    if recursive and not path.is_dir():
        raise ValidationError("Recursive dependency inventory requires a project directory")
    if path.is_dir():
        files, skipped = discover_manifests(path, recursive=recursive)
    else:
        files, skipped = [(path, path.name)], []
    sources, total = [], 0
    for manifest, origin in files:
        if linked(manifest) or not manifest.is_file():
            skipped.append(f"{origin}: skipped symlink or non-file.")
            continue
        with manifest.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValidationError("Dependency manifest exceeds 2 MiB")
        if total + len(raw) > MAX_TOTAL_BYTES:
            skipped.append("Dependency total-byte limit reached; remaining manifests unchecked.")
            break
        sources.append((origin, raw))
        total += len(raw)
    skipped.append(
        "Recursive dependency discovery enabled; excluded directories, depth/entry/file "
        "limits and unsupported formats remain unchecked."
        if recursive
        else "Root-only dependency inventory; subdirectories were not searched."
    )
    return inventory_sources(str(path), sources, not_checked=skipped, allow_paths=recursive)


def inventory_sources(target, sources, *, not_checked=(), allow_paths=False) -> Inventory:
    """Parse bounded manifest bytes; relative origins are labels, never opened as paths."""
    if not isinstance(target, str) or not target:
        raise ValidationError("Dependency inventory requires a target")
    if not isinstance(sources, (list, tuple)) or len(sources) > 20:
        raise ValidationError("At most 20 manifests per inventory")
    if type(allow_paths) is not bool:
        raise ValidationError("Relative manifest path setting must be boolean")
    names = set()
    total = 0
    for entry in sources:
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            raise ValidationError("Invalid manifest input pair")
        name, raw = entry
        if (
            not valid_source_path(name, allow_paths=allow_paths)
            or name in names
            or not isinstance(raw, bytes)
        ):
            raise ValidationError("Invalid or duplicate manifest input")
        names.add(name)
        if len(raw) > MAX_BYTES:
            raise ValidationError("Dependency manifest exceeds 2 MiB")
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise ValidationError("Dependency manifests exceed the 4 MiB total-byte limit")
    packages = {}
    missing = [
        "No packages were installed or executed; manifests are untrusted input.",
        "Only exact recorded versions; environment markers are not evaluated.",
        "Unresolved dependencies, unsupported formats and unrecorded "
        "transitive packages remain unchecked.",
    ]

    missing.extend(not_checked)
    skipped_notes = 0

    def note(message):
        nonlocal skipped_notes
        if len(missing) < 100:
            missing.append(message)
        else:
            skipped_notes += 1

    def add(ecosystem, name, version, origin):
        try:
            if not isinstance(name, str):
                raise ValidationError("Invalid name")
            name = normalize(name, ecosystem)
            Dependency(ecosystem, name, version, ())
        except ValidationError:
            note(f"{origin}: skipped unsupported package identity/version (value omitted).")
            return
        key = ecosystem, name, version
        packages.setdefault(key, set()).add(origin)
        if len(packages) > MAX_PACKAGES:
            raise ValidationError(
                "Dependency limit exceeded; narrow the scope to at most 500 packages"
            )

    for origin, raw in sources:
        basename = PurePosixPath(origin).name
        try:
            source = raw.decode("utf-8-sig")
            if basename == "go.sum":
                parse_go_sum(source, origin, add, note)
            elif basename == "Cargo.lock":
                document = tomllib.loads(source)
                if type(document.get("version")) is not int or document["version"] not in (3, 4):
                    raise ValidationError("Only Cargo lockfile versions 3 and 4 are supported")
                if not isinstance(document.get("package"), list):
                    raise ValueError
                for package in document["package"]:
                    if not isinstance(package, dict):
                        raise ValueError
                    provider = package.get("source")
                    if provider is not None and not isinstance(provider, str):
                        raise ValueError
                    if provider != "registry+https://github.com/rust-lang/crates.io-index":
                        note(
                            f"{origin}: skipped local/git/alternate registry source "
                            "(value omitted)."
                        )
                        continue
                    version = package.get("version")
                    if not _crate_version(version):
                        note(f"{origin}: skipped unsupported crate version (value omitted).")
                        continue
                    add("crates.io", package.get("name"), version, origin)
                note(
                    f"{origin}: all recorded crates.io entries included; checksum, "
                    "dependency graph, features, target and installed state unverified."
                )
            elif basename.startswith("requirements") and basename.endswith(".txt"):
                for number, line in enumerate(source.splitlines(), 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    match = re.fullmatch(
                        r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?"
                        r"\s*==\s*([^\s;]+)(?:\s*;[^#]*)?(?:\s+#.*)?",
                        line,
                    )
                    if match:
                        add("PyPI", match[1], match[2], f"{origin}:{number}")
                    else:
                        note(
                            f"{origin}:{number}: skipped unpinned/unsupported requirement "
                            "(value omitted)."
                        )
            elif basename == "package-lock.json":
                document = json.loads(source, object_pairs_hook=_pairs, parse_constant=_nonfinite)
                if type(document.get("lockfileVersion")) is not int or document[
                    "lockfileVersion"
                ] not in (2, 3):
                    raise ValidationError("Only npm lockfile versions 2 and 3 are supported")
                if not isinstance(document.get("packages"), dict):
                    raise ValueError
                for location, package in document["packages"].items():
                    if not location:
                        continue  # Root application is not an installed dependency.
                    if not isinstance(package, dict):
                        raise ValueError
                    if package.get("link") or "node_modules/" not in location:
                        note(f"{origin}: skipped workspace/link entry.")
                        continue
                    name = package.get("name") or location.rsplit("node_modules/", 1)[1]
                    add("npm", name, package.get("version"), origin)
                note(
                    f"{origin}: dev/optional/all-platform entries included; "
                    "runtime reachability unverified."
                )
            elif basename in ("uv.lock", "poetry.lock"):
                document = tomllib.loads(source)
                if not isinstance(document.get("package"), list):
                    raise ValueError
                for package in document["package"]:
                    if not isinstance(package, dict):
                        raise ValueError
                    provider = package.get("source", {})
                    if not isinstance(provider, dict):
                        raise ValueError
                    if provider and not (
                        "registry" in provider or provider.get("type") in ("legacy", "index")
                    ):
                        note(f"{origin}: skipped non-registry source (value omitted).")
                        continue
                    add("PyPI", package.get("name"), package.get("version"), origin)
                note(
                    f"{origin}: all lock groups/platforms included; installed state is unverified."
                )
            else:
                raise ValidationError(
                    "Unsupported manifest; use requirements*.txt, package-lock.json, "
                    "uv.lock, poetry.lock, Cargo.lock or go.sum"
                )
        except ValidationError as exc:
            raise ValidationError(f"Invalid dependency manifest: {origin}; {exc}") from None
        except (ValueError, UnicodeError, TypeError, AttributeError, RecursionError):
            raise ValidationError(f"Invalid or unsupported dependency manifest: {origin}") from None
    if not sources:
        note("No supported regular manifests were parsed in the selected dependency scope.")
    if skipped_notes:
        missing.append(f"Additional omitted inventory notices: {skipped_notes}.")
    return Inventory(
        target,
        tuple(
            Dependency(*key, tuple(sorted(origins))) for key, origins in sorted(packages.items())
        ),
        tuple(missing),
    )


class AdvisoryCache:
    """Opt-in plaintext package inventory/advisory cache; never reuse stale results."""

    def __init__(self, path: Path, *, ttl_seconds=3600, clock=time.time):
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 86400:
            raise ValidationError("Advisory cache TTL must be between 1 second and 24 hours")
        self.path, self.ttl, self.clock = Path(path), ttl_seconds, clock
        self.check_path(existing=False)
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            self.check_path()
        else:
            os.close(descriptor)
        with closing(self.connect()) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS advisories "
                "(key TEXT PRIMARY KEY, expires REAL, response TEXT)"
            )

    @staticmethod
    def key(package):
        return hashlib.sha256(json.dumps(package.query(), sort_keys=True).encode()).hexdigest()

    def check_path(self, *, existing=True):
        if linked(self.path) or (self.path.exists() and not self.path.is_file()):
            raise ValidationError("Advisory cache must be a regular file without links/junctions")
        if existing and not self.path.is_file():
            raise ValidationError("Existing advisory cache required; nothing was recreated")
        if self.path.is_file() and self.path.stat().st_size > 128 * 1024 * 1024:
            raise ValidationError("Advisory cache exceeds the 128 MiB local limit")

    def connect(self):
        self.check_path()
        return sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True)

    def now(self):
        value = self.clock()
        if type(value) not in (int, float) or not 0 <= value <= 10**12 or not math.isfinite(value):
            raise ValidationError("Advisory cache clock must be a bounded finite timestamp")
        return value

    @staticmethod
    def identifiers(value):
        if not isinstance(value, (list, tuple)) or len(value) > 1000 or any(
            not isinstance(item, str) or not re.fullmatch(ADVISORY_ID, item) for item in value
        ):
            raise ValidationError("Invalid advisory cache identities or entry limit exceeded")
        return sorted(set(value))

    def get(self, package):
        now = self.now()
        with closing(self.connect()) as db:
            # Bound materialization before untrusted text crosses into Python.
            row = db.execute(
                "SELECT expires, CASE WHEN typeof(response)='text' "
                "AND length(CAST(response AS BLOB))<=262144 THEN response ELSE NULL END "
                "FROM advisories WHERE key=?", (self.key(package),)
            ).fetchone()
        if row is None:
            return None
        expiry = row[0]
        if (
            type(expiry) not in (int, float) or not 0 <= expiry <= 10**12 + 86400
            or not math.isfinite(expiry)
        ):
            raise ValidationError("Invalid advisory cache expiry; no clean conclusion")
        if expiry <= now:
            return None
        if not isinstance(row[1], str):
            raise ValidationError("Invalid or oversized advisory cache response")
        try:
            value = json.loads(row[1])
        except (ValueError, RecursionError):
            raise ValidationError("Invalid advisory cache JSON; no clean conclusion") from None
        if not isinstance(value, list):
            raise ValidationError("Advisory cache response must contain an array")
        return self.identifiers(value)

    def put(self, package, identifiers):
        value = self.identifiers(identifiers)
        now = self.now()
        with closing(self.connect()) as db, db:
            db.execute(
                "INSERT OR REPLACE INTO advisories VALUES(?,?,?)",
                (self.key(package), now + self.ttl, json.dumps(value)),
            )


class OSVAudit:
    def __init__(self, client, *, cache=None, max_pages=10):
        if type(max_pages) is not int or not 1 <= max_pages <= 20:
            raise ValidationError("OSV page limit must be between 1 and 20")
        self.client, self.cache, self.max_pages = client, cache, max_pages

    def assess(self, collected: Inventory) -> dict:
        missing = list(collected.not_checked)
        findings = []
        queries, matches, complete, cache_hits = [], {}, {}, 0
        for package in collected.packages:
            cached = self.cache.get(package) if self.cache else None
            matches[package] = set(cached or [])
            complete[package] = cached is not None
            if cached is not None:
                cache_hits += 1
            else:
                queries.append((package, None))
        if sum(map(len, matches.values())) > 1000:
            raise ProviderError("Cached advisory result limit exceeded; narrow the scope")
        seen_tokens = {package: set() for package in collected.packages}
        requests = 0
        while queries and requests < self.max_pages:
            current, queries = queries[:100], queries[100:]
            body = {
                "queries": [
                    {**p.query(), **({"page_token": token} if token else {})}
                    for p, token in current
                ]
            }
            response = self.client.request(
                "https://api.osv.dev/v1/querybatch",
                method="POST",
                headers={"Content-Type": "application/json"},
                body=json.dumps(body).encode(),
            )
            requests += 1
            if response.status != 200:
                raise ProviderError(
                    f"OSV lookup returned HTTP {response.status}; no clean conclusion"
                )
            results = response.document().get("results")
            if not isinstance(results, list) or len(results) != len(current):
                raise ProviderError("OSV response does not match the queried packages")
            for (package, _previous_token), result in zip(current, results, strict=True):
                if not isinstance(result, dict) or not isinstance(result.get("vulns", []), list):
                    raise ProviderError("OSV response contains invalid vulnerability results")
                for entry in result.get("vulns", []):
                    identifier = entry.get("id") if isinstance(entry, dict) else None
                    if not isinstance(identifier, str) or not re.fullmatch(ADVISORY_ID, identifier):
                        raise ProviderError("OSV returned an invalid advisory identity")
                    matches[package].add(identifier)
                if sum(map(len, matches.values())) > 1000:
                    raise ProviderError(
                        "Advisory result limit exceeded; narrow the dependency scope"
                    )
                token = result.get("next_page_token")
                if token is not None and (not isinstance(token, str) or len(token) > 4096):
                    raise ProviderError("OSV returned an invalid pagination token")
                if token:
                    if token in seen_tokens[package]:
                        raise ProviderError(
                            "OSV repeated a pagination token; results are incomplete"
                        )
                    seen_tokens[package].add(token)
                    queries.append((package, token))
                else:
                    complete[package] = True
                    if self.cache:
                        self.cache.put(package, sorted(matches[package]))
        for package, identifiers in matches.items():
            for identifier in sorted(identifiers):
                findings.append(
                    AssessmentFinding(
                        "known_dependency_advisory",
                        "candidate",
                        f"{package.ecosystem}:{package.name}@{package.version}: {identifier}; "
                        f"https://osv.dev/vulnerability/{identifier}",
                        "Review advisory applicability and fixed releases; update the lockfile "
                        "and test. "
                        "A version match does not prove runtime exploitability.",
                    )
                )
        if queries:
            missing.append(
                "OSV page/request limit reached; some packages have incomplete advisory results."
            )
        missing.extend(
            (
                "OSV IDs are version matches, not confirmed exploitable vulnerabilities.",
                "Severity, aliases, fix versions and reachability were not retrieved or inferred.",
                "Unknown packages or no matches do not establish security; "
                "database coverage varies.",
            )
        )
        result = asdict(
            AssessmentResult(
                collected.target, "dependency_manifest", "partial", tuple(findings), tuple(missing)
            )
        )
        result["dependency_audit"] = {
            "packages": len(collected.packages),
            "cache_hits": cache_hits,
            "network_requests": requests,
            "complete_queries": sum(complete.values()),
        }
        return result
