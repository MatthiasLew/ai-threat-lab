"""Inert generated acceptance inputs, never executable payloads or real recipients."""

from email.message import EmailMessage


def synthetic_header_capture():
    return {
        "schema_version": 1,
        "url": "https://website.example.invalid/training",
        "status": 200,
        "headers": [
            ["Strict-Transport-Security", "max-age=31536000"],
            ["Content-Security-Policy", "script-src * 'unsafe-inline' 'unsafe-eval'"],
            ["X-Content-Type-Options", "nosniff"],
            ["Referrer-Policy", "no-referrer"],
            ["Set-Cookie", "training=INERT-DEMO-VALUE; SameSite=None"],
            ["Set-Cookie", "preferences=INERT; Secure; HttpOnly; SameSite=Lax"],
        ],
    }


def synthetic_cargo_lock():
    return (
        'version = 4\n[[package]]\nname = "fixture-crate-offline-example"\n'
        'version = "1.2.3"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )


def synthetic_message():
    message = EmailMessage()
    message["From"] = "Fictional sender <sender@example.invalid>"
    message["To"] = "Fictional recipient <recipient@example.invalid>"
    message["Subject"] = "LOCAL SYNTHETIC REVIEW FIXTURE"
    message.set_content(
        '<a href="http://192.0.2.1/training">https://office.example.invalid/</a>',
        subtype="html",
    )
    message.add_attachment(
        b"INERT TRAINING BYTES; NOT AN EXECUTABLE",
        maintype="application",
        subtype="octet-stream",
        filename="fictional-report.pdf.exe",
    )
    return message.as_bytes()


def synthetic_kubernetes_manifest():
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "fictional-offline-pod"},
        "spec": {
            "hostNetwork": True,
            "securityContext": {
                "runAsUser": 0,
                "runAsNonRoot": False,
                "seccompProfile": {"type": "Unconfined"},
            },
            "volumes": [{"name": "fictional-volume", "hostPath": {"path": "/fictional/host"}}],
            "containers": [
                {
                    "name": "fictional-container",
                    "image": "example.invalid/inert:fixture",
                    "securityContext": {
                        "privileged": True,
                        "allowPrivilegeEscalation": True,
                        "readOnlyRootFilesystem": False,
                        "capabilities": {"add": ["SYS_ADMIN"]},
                    },
                    "ports": [{"containerPort": 8080, "hostPort": 8080}],
                }
            ],
        },
    }


def synthetic_go_sum():
    """Fictional module and syntactically valid h1 field; never fetched/verified."""
    return "example.invalid/fixture-module v1.2.3 h1:" + "A" * 43 + "=\n"


def synthetic_python_flow():
    """Flask/SQLite source is parsed only; neither framework nor commands are run."""
    return (
        "from flask import request\nimport os, sqlite3\n"
        "def inspect_example():\n"
        "    value = request.args.get('fixture')\n"
        "    command = 'fixture-command ' + value\n"
        "    os.system(command)\n"
        "    connection = sqlite3.connect(':memory:')\n"
        "    query = 'SELECT fixture FROM sample WHERE name = ' + value\n"
        "    connection.execute(query)\n"
    )


def synthetic_python_control_flow():
    """Inert branch and loop fixture; parsed without importing Flask or executing SQL."""
    return (
        "from flask import request\nimport os, sqlite3\n"
        "def inspect_example():\n"
        "    if condition:\n"
        "        value = request.args.get('fixture')\n"
        "    else:\n"
        "        value = 'fixed'\n"
        "    os.system(value)\n"
        "    connection = sqlite3.connect(':memory:')\n"
        "    for term in request.args.getlist('fixture'):\n"
        "        connection.execute('SELECT ' + term)\n"
    )


def synthetic_python_local_calls():
    """Inert argument and return propagation through previously defined local helpers."""
    return (
        "from flask import request\nimport os, sqlite3\n"
        "def prepare(value):\n"
        "    return 'fixture ' + value\n"
        "def inspect_example(connection, value):\n"
        "    os.system(value)\n"
        "    connection.execute('SELECT ' + value)\n"
        "def endpoint():\n"
        "    value = prepare(request.args.get('fixture'))\n"
        "    inspect_example(sqlite3.connect(':memory:'), value)\n"
    )


def synthetic_python_project():
    """Two inert root modules; all imports and helper calls are statically interpreted."""
    return {
        "app.py": (
            "from flask import request\nimport sqlite3\n"
            "from helpers import prepare, inspect_example\n"
            "def endpoint():\n"
            "    value = prepare(request.args.get('fixture'))\n"
            "    inspect_example(sqlite3.connect(':memory:'), value)\n"
        ),
        "helpers.py": (
            "import os\n"
            "def prepare(value):\n    return 'fixture ' + value\n"
            "def inspect_example(connection, value):\n"
            "    os.system(value)\n"
            "    connection.execute('SELECT ' + value)\n"
        ),
    }


def synthetic_python_package():
    """Inert regular src package with a relative helper import."""
    sources = synthetic_python_project()
    return {
        "src/example/__init__.py": "",
        "src/example/views.py": sources["app.py"].replace(
            "from helpers import", "from .helpers import"
        ),
        "src/example/helpers.py": sources["helpers.py"],
    }


def synthetic_python_importlib():
    """Inert literal importlib call; no target module is imported at runtime."""
    sources = synthetic_python_package()
    sources["src/example/views.py"] = (
        "from flask import request\nimport sqlite3\n"
        "from importlib import import_module as load\n"
        "def endpoint():\n"
        "    helpers = load('.helpers', package='example')\n"
        "    value = helpers.prepare(request.args.get('fixture'))\n"
        "    helpers.inspect_example(sqlite3.connect(':memory:'), value)\n"
    )
    return sources


def synthetic_python_sqlite_context():
    """Parsed-only default SQLite context with three candidate observations."""
    return (
        "from flask import request\nimport os, sqlite3\n"
        "def endpoint():\n"
        "    with sqlite3.connect(':memory:') as connection:\n"
        "        value = request.args.get('fixture')\n"
        "        connection.execute('SELECT ' + value)\n"
        "        os.system(value)\n"
    )


def synthetic_python_package_shadowing(*, shadowed):
    """Paired static controls for absent versus assigned package attributes."""
    sources = synthetic_python_package()
    sources["src/example/__init__.py"] = "helpers = 42\n" if shadowed else ""
    sources["src/example/views.py"] = (
        "from flask import request\nimport sqlite3\n"
        "from example import helpers\n"
        "def endpoint():\n"
        "    value = helpers.prepare(request.args.get('fixture'))\n"
        "    helpers.inspect_example(sqlite3.connect(':memory:'), value)\n"
    )
    return sources


def synthetic_html(*, safer=False):
    if safer:
        return (
            '<form method="post" action="https://website.example.invalid/login">'
            '<input type="password" name="fictional"></form>'
            '<script src="https://website.example.invalid/widget.js"></script>'
        )
    return (
        '<form action="http://other.example.invalid/login">'
        '<input type="password" name="fictional"></form>\n'
        '<script src="http://cdn.example.invalid/widget.js"></script>'
    )


def synthetic_zip():
    import io
    import zipfile

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("../fictional.txt", b"INERT DEMO BYTES")
        archive.writestr("CON.txt", b"INERT DEMO BYTES")
    return stream.getvalue()


def synthetic_auth_log(*, negative=False):
    import json
    from datetime import datetime, timedelta, timezone

    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = []

    def add(second, account, source, outcome="failure"):
        events.append(
            {
                "timestamp": (start + timedelta(seconds=second)).isoformat(),
                "account": account,
                "source": source,
                "outcome": outcome,
                "method": "password",
            }
        )

    if negative:
        for i in range(5):
            add(i * 301, "fixture-account", "fixture-source")
    else:
        for i in range(5):
            add(i, "fixture-account", "fixture-source")
        add(5, "fixture-account", "fixture-source", "success")
        for i in range(5):
            add(10 + i, "fixture-target-" + str(i), "fixture-spray-source")
            add(20 + i, "fixture-distributed-account", "fixture-origin-" + str(i % 3))
    return "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n"


def synthetic_ssh_journal(*, negative=False):
    """Inert single-host OpenSSH-shaped export; no journal collection."""
    import json
    from datetime import datetime, timezone

    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    sources = {}
    rows = [{"_COMM": "unrelated", "MESSAGE": "inert ignored row"}]
    for line in synthetic_auth_log(negative=negative).splitlines():
        event = json.loads(line)
        source = sources.setdefault(event["source"], "192.0.2." + str(len(sources) + 1))
        delta = datetime.fromisoformat(event["timestamp"]) - epoch
        microseconds = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
        state = "Accepted" if event["outcome"] == "success" else "Failed"
        rows.append(
            {
                "_COMM": "sshd-session",
                "_MACHINE_ID": "a" * 32,
                "__REALTIME_TIMESTAMP": str(microseconds),
                "MESSAGE": f"{state} password for {event['account']} from {source} port 54321 ssh2",
            }
        )
    return "\n".join(json.dumps(row) for row in rows) + "\n"
