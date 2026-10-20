"""Independent quality benchmark for static and passive analyzers (TP, FP, FN, Unsupported)."""

import io
import json
import zipfile

from ai_threat_lab.archive_review import zip_metadata
from ai_threat_lab.auth_log_review import inspect_auth_log
from ai_threat_lab.code_review import review_source
from ai_threat_lab.config_review import inspect_configuration
from ai_threat_lab.header_review import inspect_response_headers
from ai_threat_lab.html_review import inspect_html
from ai_threat_lab.kubernetes_review import review_kubernetes_source
from ai_threat_lab.local_inventory import local_inventory
from ai_threat_lab.office_review import review_office

PYTHON_VULNERABLE_SAMPLES = (
    ("eval_call", "eval(user_supplied_expr)\n", "PY001"),
    ("subprocess_shell", "import subprocess\nsubprocess.run(cmd, shell=True)\n", "PY002"),
    ("pickle_loads", "import pickle\npickle.loads(untrusted_bytes)\n", "PY003"),
    ("requests_no_verify", "import requests\nrequests.get(url, verify=False)\n", "PY004"),
    ("os_system", "import os\nos.system(command_line)\n", "PY005"),
    ("tempfile_mktemp", "import tempfile\ntempfile.mktemp()\n", "PY006"),
    ("unverified_ssl", "import ssl\nssl._create_unverified_context()\n", "PY007"),
    ("unsafe_yaml", "import yaml\nyaml.load(stream, Loader=yaml.Loader)\n", "PY008"),
    ("weak_md5", "import hashlib\nhashlib.md5(data)\n", "PY009"),
    (
        "flask_sqli_flow",
        (
            "from flask import Flask, request\n"
            "import sqlite3\n"
            "app = Flask(__name__)\n"
            "@app.route('/items')\n"
            "def items():\n"
            "    name = request.args.get('name')\n"
            "    db = sqlite3.connect('app.db')\n"
            "    return str(db.execute(f'SELECT * FROM items WHERE name = {name}'))\n"
        ),
        "PY014",
    ),
)

PYTHON_SAFE_SYNTACTICALLY_SIMILAR_SAMPLES = (
    ("literal_eval", "import ast\nast.literal_eval(user_supplied_expr)\n"),
    ("subprocess_list", "import subprocess\nsubprocess.run(['ls', '-l'], shell=False)\n"),
    ("json_loads", "import json\njson.loads(untrusted_text)\n"),
    ("requests_verified", "import requests\nrequests.get(url, verify=True)\n"),
    ("tempfile_mkstemp", "import tempfile\ntempfile.mkstemp()\n"),
    ("default_ssl", "import ssl\nssl.create_default_context()\n"),
    ("safe_yaml", "import yaml\nyaml.safe_load(stream)\n"),
    ("sha256_digest", "import hashlib\nhashlib.sha256(data)\n"),
    (
        "md5_non_security",
        "import hashlib\nhashlib.md5(data, usedforsecurity=False)\n",
    ),
    (
        "flask_parameterized_sql",
        (
            "from flask import Flask, request\n"
            "import sqlite3\n"
            "app = Flask(__name__)\n"
            "@app.route('/items')\n"
            "def items():\n"
            "    name = request.args.get('name')\n"
            "    db = sqlite3.connect('app.db')\n"
            "    return str(db.execute('SELECT * FROM items WHERE name = ?', (name,)))\n"
        ),
    ),
)


def compute_benchmark_metrics(tmp_path):
    tp = fp = fn = tn = unsupported = 0

    # 1. Python AST & Data-Flow
    for name, source, expected_rule in PYTHON_VULNERABLE_SAMPLES:
        result = review_source(source, filename=f"{name}.py")
        rules = {f.rule_id for f in result.findings}
        if expected_rule in rules:
            tp += 1
        else:
            fn += 1

    for name, source in PYTHON_SAFE_SYNTACTICALLY_SIMILAR_SAMPLES:
        result = review_source(source, filename=f"{name}.py")
        if result.findings:
            fp += 1
        else:
            tn += 1

    # 2. Configuration & Kubernetes
    docker_vuln = inspect_configuration(
        "Dockerfile", "FROM python:3.12\nUSER root\nADD https://example.com/a.tar /app/\n"
    )
    if {"container_mutable_base", "container_explicit_root", "container_remote_add"} <= {
        f.check for f in docker_vuln
    }:
        tp += 1
    else:
        fn += 1

    docker_safe = inspect_configuration(
        "Dockerfile",
        "FROM python@sha256:" + "a" * 64 + "\nUSER 10001\nCOPY app.py /app/app.py\n",
    )
    if docker_safe:
        fp += 1
    else:
        tn += 1

    wf_vuln = inspect_configuration(
        ".github/workflows/ci.yml",
        "permissions: write-all\nsteps:\n  - uses: actions/checkout@v4\n",
    )
    if {"workflow_write_all", "workflow_mutable_action"} <= {f.check for f in wf_vuln}:
        tp += 1
    else:
        fn += 1

    wf_safe = inspect_configuration(
        ".github/workflows/ci.yml",
        "permissions: read-all\nsteps:\n  - uses: actions/checkout@" + "b" * 40 + "\n",
    )
    if wf_safe:
        fp += 1
    else:
        tn += 1

    k8s_vuln = review_kubernetes_source(
        json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "vuln-pod"},
                "spec": {
                    "hostNetwork": True,
                    "containers": [
                        {
                            "name": "app",
                            "image": "nginx:latest",
                            "securityContext": {"privileged": True},
                        }
                    ],
                },
            }
        ),
        "vuln-pod.json",
        explicit=True,
    )
    if k8s_vuln.findings:
        tp += 1
    else:
        fn += 1

    k8s_safe = review_kubernetes_source(
        json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "safe-pod", "namespace": "prod"},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "app",
                            "image": "nginx@sha256:" + "c" * 64,
                            "resources": {
                                "limits": {"cpu": "500m", "memory": "256Mi"},
                                "requests": {"cpu": "100m", "memory": "128Mi"},
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "runAsNonRoot": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }
                    ],
                },
            }
        ),
        "safe-pod.json",
        explicit=True,
    )
    if k8s_safe.findings:
        fp += 1
    else:
        tn += 1

    # 3. HTML & HTTP Headers
    html_vuln, _ = inspect_html(
        '<html><body><form action="http://example.com/login" method="post">'
        '<input type="password" name="pw"></form>'
        '<script src="https://cdn.example.com/app.js"></script></body></html>',
        document_url="https://app.example.com/login",
    )
    if html_vuln:
        tp += 1
    else:
        fn += 1

    html_safe, _ = inspect_html(
        '<html><body><form action="https://app.example.com/login" method="post">'
        '<input type="hidden" name="csrf_token" value="1">'
        '<input type="password" name="pw" autocomplete="off"></form>'
        '<script src="https://cdn.example.com/app.js" '
        'integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" '
        'crossorigin="anonymous"></script></body></html>',
        document_url="https://app.example.com/login",
    )
    if html_safe:
        fp += 1
    else:
        tn += 1

    hdr_vuln, _ = inspect_response_headers(
        200,
        [("Server", "Apache/2.4.1"), ("Access-Control-Allow-Origin", "*")],
    )
    if hdr_vuln:
        tp += 1
    else:
        fn += 1

    hdr_safe, _ = inspect_response_headers(
        200,
        [
            ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
            ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Permissions-Policy", "geolocation=()"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
        ],
    )
    if hdr_safe:
        fp += 1
    else:
        tn += 1

    # 4. Archives, Office & Mail
    zip_vuln_buf = io.BytesIO()
    with zipfile.ZipFile(zip_vuln_buf, "w") as zf:
        zf.writestr("../escape.txt", "traversal")
    zip_vuln, _ = zip_metadata(zip_vuln_buf.getvalue())
    if any(f.check == "zip_path_escape" for f in zip_vuln):
        tp += 1
    else:
        fn += 1

    zip_safe_buf = io.BytesIO()
    with zipfile.ZipFile(zip_safe_buf, "w") as zf:
        zf.writestr("docs/readme.txt", "clean")
    zip_safe, _ = zip_metadata(zip_safe_buf.getvalue())
    if any(f.status == "candidate" for f in zip_safe):
        fp += 1
    else:
        tn += 1

    office_vuln_path = tmp_path / "macro.docm"
    with zipfile.ZipFile(office_vuln_path, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Override PartName="/word/vbaProject.bin" '
            'ContentType="application/vnd.ms-office.vbaProject"/></Types>',
        )
        zf.writestr("word/document.xml", "<w:document/>")
        zf.writestr("word/vbaProject.bin", b"macro-placeholder")
    office_vuln, _ = review_office(office_vuln_path)
    if any(f.check == "office_macro_declarations" for f in office_vuln.findings):
        tp += 1
    else:
        fn += 1

    office_safe_path = tmp_path / "clean.docx"
    with zipfile.ZipFile(office_safe_path, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        zf.writestr("word/document.xml", "<w:document/>")
    office_safe, _ = review_office(office_safe_path)
    if any(f.status == "candidate" for f in office_safe.findings):
        fp += 1
    else:
        tn += 1

    eml_path = tmp_path / "phish.eml"
    eml_path.write_bytes(
        b"From: CEO <ceo@example.com>\r\n"
        b"Reply-To: attacker@evil.invalid\r\n"
        b"Subject: Urgent wire transfer\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Click http://198.51.100.10/login immediately.\r\n"
    )
    eml_vuln = local_inventory(str(eml_path))
    if any(f.status == "candidate" for f in eml_vuln.findings):
        tp += 1
    else:
        fn += 1

    # 5. Auth logs
    auth_vuln = inspect_auth_log(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": f"2026-01-01T00:00:0{i}Z",
                        "outcome": "failure",
                        "account": "admin",
                        "source": "198.51.100.25",
                        "method": "password",
                    }
                )
                for i in range(5)
            ]
            + [
                json.dumps(
                    {
                        "timestamp": "2026-01-01T00:00:06Z",
                        "outcome": "success",
                        "account": "admin",
                        "source": "198.51.100.25",
                        "method": "password",
                    }
                )
            ]
        )
    )
    if any(f.check == "auth_success_after_failures" for f in auth_vuln.findings):
        tp += 1
    else:
        fn += 1

    auth_safe = inspect_auth_log(
        json.dumps(
            {
                "timestamp": "2026-01-01T00:00:01Z",
                "outcome": "success",
                "account": "alice",
                "source": "192.0.2.10",
                "method": "password",
            }
        )
    )
    if auth_safe.findings:
        fp += 1
    else:
        tn += 1

    # 6. Unsupported & Out-of-Scope Cases Explicitly Flagged in not_checked
    proj = tmp_path / "unsupported_project"
    proj.mkdir()
    (proj / "dynamic_loader.py").write_text(
        "import importlib\n"
        "def load_plugin(name):\n"
        "    mod = importlib.import_module(name)\n"
        "    return mod\n",
        encoding="utf-8",
    )
    (proj / "broken.js").write_bytes(b"\xff\xfe\xfd")
    (proj / "oversized.py").write_text("x = 1\n" * 60000, encoding="utf-8")
    inv = local_inventory(str(proj))
    if any(
        "dynamic import" in item.lower() or "importlib" in item.lower()
        for item in inv.not_checked
    ):
        unsupported += 1
    if any("could not read" in item.lower() for item in inv.not_checked):
        unsupported += 1
    if any("oversized" in item.lower() for item in inv.not_checked):
        unsupported += 1

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "unsupported_explicitly_marked": unsupported,
    }


def test_analyzer_quality_benchmark_tp_fp_fn_and_unsupported(tmp_path):
    metrics = compute_benchmark_metrics(tmp_path)
    assert metrics == {
        "true_positives": 19,
        "false_positives": 0,
        "false_negatives": 0,
        "true_negatives": 18,
        "unsupported_explicitly_marked": 3,
    }


def test_heuristic_and_ambiguous_cases_never_claim_confirmed_vulnerability(tmp_path):
    """Heuristic observations must always remain candidate/unverified and state limitations."""
    ambiguous = review_source(
        "import hashlib\n"
        "def checksum_or_password(blob):\n"
        "    return hashlib.sha1(blob).hexdigest()\n",
        filename="ambiguous.py",
    )
    assert len(ambiguous.findings) == 1
    assert ambiguous.findings[0].rule_id == "PY009"
    assert "does not determine whether the use is cryptographic" in ambiguous.findings[0].rationale
    assert any(
        "candidates, not validated vulnerabilities" in item for item in ambiguous.limitations
    )

    sample_file = tmp_path / "ambiguous.py"
    sample_file.write_text("import os\nos.system('echo hello')\n", encoding="utf-8")
    report = local_inventory(str(sample_file))
    assert report.status == "partial"
    assert all(f.status in ("candidate", "unverified") for f in report.findings)
    assert report.not_checked
