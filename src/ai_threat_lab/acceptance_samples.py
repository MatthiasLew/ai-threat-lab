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
