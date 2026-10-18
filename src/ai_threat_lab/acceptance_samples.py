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
