"""Generate sample PDF reports for documentation and review."""

from pathlib import Path

from ai_threat_lab.pdf_report import generate_pdf_report

out_dir = Path("docs/samples")
out_dir.mkdir(parents=True, exist_ok=True)

# Sample report with realistic findings
sample_report = {
    "status": "candidate_findings",
    "target": "c:/Users/Developer/workspace/ecommerce-backend",
    "generated_at": "2026-10-20T22:30:00Z",
    "summary": {
        "unique_findings": 3,
        "triage_counts": {
            "P1": 1,
            "P2": 1,
            "P3": 1,
            "P4": 0,
        },
    },
    "findings": [
        {
            "id": "SEC-001",
            "evidence_id": "SEC-001",
            "rule_code": "SEC_SUBPROCESS_SHELL",
            "title": "Wykryto subprocess.run z shell=True / Subprocess execution with shell=True",
            "triage_priority": "P1",
            "confirmation_status": "candidate",
            "target": "src/tasks/exporter.py",
            "file_path": "src/tasks/exporter.py",
            "line_number": 42,
            "mechanism": (
                "Uruchomienie powłoki systemowej z parametrem shell=True w połączeniu "
                "z niezweryfikowanymi danymi wejściowymi pozwala osobie atakującej na "
                "wykonanie dowolnych poleceń w systemie operacyjnym serwera."
            ),
            "recommendation": (
                "Zastąp wywołanie shell=True przekazaniem listy argumentów: "
                "subprocess.run(['tar', '-czf', archive, path], check=True, shell=False)."
            ),
        },
        {
            "id": "SEC-002",
            "evidence_id": "SEC-002",
            "rule_code": "SEC_HARDCODED_API_KEY",
            "title": "Podejrzenie zahardkodowanego klucza API / Potential hardcoded API secret",
            "triage_priority": "P2",
            "confirmation_status": "candidate",
            "target": "src/config/integrations.py",
            "file_path": "src/config/integrations.py",
            "line_number": 15,
            "mechanism": (
                "Klucz uwierzytelniający do zewnętrznego dostawcy został umieszczony "
                "bezpośrednio w kodzie źródłowym, co grozi jego wyciekiem do repozytorium git."
            ),
            "recommendation": (
                "Przenieś klucz do zmiennych środowiskowych lub bezpiecznego menedżera "
                "sekretów (np. os.environ['INTEGRATION_KEY']) i dodaj go do pliku .env.example."
            ),
        },
        {
            "id": "SEC-003",
            "evidence_id": "SEC-003",
            "rule_code": "SEC_INSECURE_HASH",
            "title": "Użycie przestarzałej funkcji skrótu MD5 / Insecure hash MD5",
            "triage_priority": "P3",
            "confirmation_status": "candidate",
            "target": "src/utils/checksum.py",
            "file_path": "src/utils/checksum.py",
            "line_number": 28,
            "mechanism": (
                "Algorytm MD5 jest podatny na kolizje kryptograficzne i nie powinien "
                "być stosowany w mechanizmach weryfikacji integralności ani bezpieczeństwa."
            ),
            "recommendation": "Zastąp hashlib.md5 bezpiecznym algorytmem hashlib.sha256.",
        },
    ],
    "not_checked": [
        {
            "tool_id": "dynamic_taint_tracking",
            "reason": (
                "Statyczna analiza offline nie śledzi przepływu danych w czasie wykonania programu."
            ),
        },
        {
            "tool_id": "network_port_audit",
            "reason": (
                "Tryb audytu offline zabrania wysyłania pakietów sieciowych do badanych hostów."
            ),
        },
        {
            "tool_id": "binary_dependency_decompilation",
            "reason": "Zewnętrzne skompilowane biblioteki C (.dll/.so) zostały pominięte.",
        },
    ],
    "notice": (
        "Wszelkie wykrycia stanowią kandydatów wygenerowanych deterministycznie w trybie offline. "
        "Wymagają ręcznej weryfikacji kontekstu biznesowego przez inżyniera oprogramowania."
    ),
}

# Sample Gemini AI review advisory
sample_ai_review_pl = {
    "provider": "gemini",
    "model": "gemini-2.5-flash",
    "interpretation": {
        "summary": (
            "Audytowany kod zawiera krytyczny punkt ryzyka związany z wykonaniem poleceń powłoki "
            "w module eksportu oraz wyciek danych uwierzytelniających. Wdrożenie rekomendacji "
            "zabezpieczy aplikację przed zdalnym przejęciem środowiska wykonawczego."
        ),
        "observations": [
            {
                "evidence_id": "SEC-001",
                "assessment": "Potwierdzone wysokie ryzyko Command Injection w module exporter.py.",
                "business_impact": (
                    "Potencjalne przejęcie uprawnień serwisowych i dostęp do bazy klientów."
                ),
                "safe_fix": "Użyj shlex.split lub listy argumentów bez powłoki systemowej.",
            },
            {
                "evidence_id": "SEC-002",
                "assessment": (
                    "Ryzyko nieautoryzowanego użycia API i naliczenia kosztów u dostawcy."
                ),
                "business_impact": "Straty finansowe oraz naruszenie tajemnicy handlowej.",
                "safe_fix": (
                    "Unieważnij obecny klucz w konsoli dostawcy i wstrzyknij nowy ze zmiennych."
                ),
            },
            {
                "evidence_id": "SEC-003",
                "assessment": "Niska krytyczność, o ile skrót nie służy do przechowywania haseł.",
                "business_impact": (
                    "Podatność na fałszowanie sum kontrolnych w warunkach kolizyjnych."
                ),
                "safe_fix": "Zmigruj schemat bazy do skrótów SHA-256.",
            },
        ],
    },
}

sample_ai_review_en = {
    "provider": "gemini",
    "model": "gemini-2.5-flash",
    "interpretation": {
        "summary": (
            "The inspected codebase contains a high-priority command injection vulnerability in "
            "the export task and hardcoded credentials. Implementing the suggested remediations "
            "will protect the production environment against unauthorized takeover."
        ),
        "observations": [
            {
                "evidence_id": "SEC-001",
                "assessment": "Confirmed high-severity Command Injection risk in exporter.py.",
                "business_impact": (
                    "Unauthorized shell execution leading to server compromise and data loss."
                ),
                "safe_fix": (
                    "Pass command arguments as a list and disable shell execution (shell=False)."
                ),
            },
            {
                "evidence_id": "SEC-002",
                "assessment": "Credential exposure risking unauthorized third-party API access.",
                "business_impact": (
                    "Financial loss and violation of confidential communication channels."
                ),
                "safe_fix": (
                    "Revoke key in provider dashboard and inject via environment variables."
                ),
            },
            {
                "evidence_id": "SEC-003",
                "assessment": "Cryptographic weakness if MD5 is used for authentication.",
                "business_impact": "Susceptibility to hash collision attacks.",
                "safe_fix": "Migrate checksum generation to SHA-256.",
            },
        ],
    },
}

if __name__ == "__main__":
    # Generate Polish sample
    pdf_pl = generate_pdf_report(
        sample_report,
        ai_review=sample_ai_review_pl,
        language="pl",
        project_name="Sklep Internetowy — Backend API",
    )
    pl_path = out_dir / "sample_audit_pl.pdf"
    pl_path.write_bytes(pdf_pl)
    print(f"Generated Polish sample PDF: {pl_path} ({len(pdf_pl)} bytes)")

    # Generate English sample
    pdf_en = generate_pdf_report(
        sample_report,
        ai_review=sample_ai_review_en,
        language="en",
        project_name="E-Commerce Backend API",
    )
    en_path = out_dir / "sample_audit_en.pdf"
    en_path.write_bytes(pdf_en)
    print(f"Generated English sample PDF: {en_path} ({len(pdf_en)} bytes)")
