"""Structured security finding details and offline developer explanations.

Enriches candidate and unverified observations with deterministic, non-AI explanations
covering what was detected, why it is dangerous, potential consequences, practical fixes,
verification steps, and explicit analyzer limitations in English ('en') or Polish ('pl').
Never invents line numbers and never elevates heuristic findings to confirmed status.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .assessment import AssessmentFinding, AssessmentResult
from .audit_report import PRIORITIES
from .code_review import CodeFinding, CodeReviewResult
from .models import ValidationError

SUPPORTED_LANGUAGES = {
    "en": "English",
    "pl": "Polish",
}


def validate_report_language(language: str) -> str:
    if not isinstance(language, str) or language not in SUPPORTED_LANGUAGES:
        supported = ", ".join(sorted(SUPPORTED_LANGUAGES))
        raise ValidationError(f"Unsupported report language; choose one of: {supported}")
    return language


@dataclass(frozen=True)
class DetailedFinding:
    id: str
    rule_code: str
    title: str
    threat_category: str
    target: str
    file_path: str | None
    line_number: int | None
    line_range: str | None
    evidence: str
    what_was_detected: str
    mechanism: str
    consequences: str
    recommendation: str
    code_example: str | None
    verification_steps: str
    analysis_limitations: str
    confirmation_status: str
    triage_priority: str
    language: str = "en"

    def to_dict(self) -> dict:
        return asdict(self)


# Rule knowledge base: (category, title_en, title_pl, mechanism_en, mechanism_pl,
# consequences_en, consequences_pl, example_code, verify_en, verify_pl, limits_en, limits_pl)
_RULE_CATALOG: dict[str, dict[str, str | None]] = {
    "PY001": {
        "category": "code_execution",
        "title_en": "Dynamic Python code execution (eval/exec)",
        "title_pl": "Dynamiczne wykonanie kodu Python (eval/exec)",
        "mechanism_en": (
            "The code invokes Python's eval() or exec() built-in. If attacker-controlled "
            "or externally supplied data reaches the expression string, Python parses and "
            "executes it with the full privileges of the running process."
        ),
        "mechanism_pl": (
            "Kod wywołuje wbudowaną funkcję eval() lub exec(). Jeżeli do przekazywanego "
            "łańcucha znaków trafią dane kontrolowane przez użytkownika lub zewnętrzne źródło, "
            "interpreter wykona dowolny kod Python z uprawnieniami procesu."
        ),
        "consequences_en": (
            "Arbitrary code execution in the application context, unauthorized data access, "
            "or compromise of the host environment if unvalidated input reaches this call."
        ),
        "consequences_pl": (
            "Wykonanie dowolnego kodu w kontekście aplikacji, nieautoryzowany dostęp do danych "
            "lub przejęcie środowiska uruchomieniowego, jeśli do wywołania trafią niezaufane dane."
        ),
        "example": (
            "# Replace dynamic eval() with a safe parser:\n"
            "import ast\n"
            "import json\n\n"
            "parsed = json.loads(raw_text)  # or ast.literal_eval(raw_text) for literals"
        ),
        "verify_en": (
            "Replace eval/exec with json.loads(), ast.literal_eval(), or an explicit dispatch "
            "table, run unit tests, and re-run `ai-threat-lab inspect` to confirm PY001 is gone."
        ),
        "verify_pl": (
            "Zastąp eval/exec przez json.loads(), ast.literal_eval() lub jawną mapę dozwolonych "
            "operacji, uruchom testy jednostkowe i ponownie wykonaj `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Static AST match only; the analyzer did not execute the program or verify whether "
            "external unvalidated input actually reaches this call at runtime."
        ),
        "limits_pl": (
            "Wyłącznie statyczne dopasowanie drzewa AST; analizator nie uruchomił programu ani "
            "nie potwierdził, czy w czasie wykonania do wywołania docierają niezaufane dane."
        ),
    },
    "PY002": {
        "category": "command_injection",
        "title_en": "Subprocess call with shell=True enabled",
        "title_pl": "Wywołanie subprocess z włączoną opcją shell=True",
        "mechanism_en": (
            "Passing shell=True delegates command parsing to the system shell "
            "(/bin/sh or cmd.exe). "
            "Shell metacharacters (;, |, &&, $(), backticks) in interpolated arguments are "
            "interpreted as separate shell commands."
        ),
        "mechanism_pl": (
            "Ustawienie shell=True przekazuje interpretację polecenia do powłoki systemowej. "
            "Znaki specjalne powłoki (;, |, &&, $()) w łączonych argumentach mogą zostać "
            "zinterpretowane jako dodatkowe polecenia systemowe."
        ),
        "consequences_en": (
            "Operating-system command injection if any portion of the command string originates "
            "from unvalidated input, filenames, or environment data."
        ),
        "consequences_pl": (
            "Wstrzyknięcie poleceń systemu operacyjnego (Command Injection), jeśli jakakolwiek "
            "część polecenia pochodzi z niezaufanego wejścia lub nazw plików."
        ),
        "example": (
            "# Pass an explicit argument list with shell=False:\n"
            "import subprocess\n\n"
            'subprocess.run(["git", "status", "--porcelain"], shell=False, check=True)'
        ),
        "verify_en": (
            "Convert the command to a list of discrete string arguments with shell=False, "
            "validate allowed arguments, and re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Przekaż polecenie jako listę osobnych argumentów z shell=False, zwaliduj "
            "dozwolone parametry i ponownie uruchom `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "AST check detects literal shell=True on subprocess calls; it does not prove that "
            "the command argument is attacker-controlled."
        ),
        "limits_pl": (
            "Analiza AST wykrywa literalne shell=True; nie rozstrzyga, czy treść polecenia "
            "jest kontrolowana przez atakującego."
        ),
    },
    "PY003": {
        "category": "deserialization",
        "title_en": "Potentially unsafe pickle deserialization",
        "title_pl": "Potencjalnie niebezpieczna deserializacja pickle",
        "mechanism_en": (
            "Python's pickle protocol is a stack-based virtual machine that can instantiate "
            "arbitrary callables via __reduce__ during deserialization."
        ),
        "mechanism_pl": (
            "Protokół pickle w Pythonie pozwala na wywołanie dowolnych obiektów i funkcji "
            "(poprzez metodę __reduce__) już w trakcie odczytu strumienia bajtów."
        ),
        "consequences_en": (
            "Immediate arbitrary code execution if the byte stream or file can be modified "
            "or supplied by an unvalidated party."
        ),
        "consequences_pl": (
            "Natychmiastowe wykonanie dowolnego kodu w przypadku wczytania danych pickle "
            "pochodzących z niezaufanego lub zmodyfikowanego źródła."
        ),
        "example": (
            "# Use a data-only serialization format such as JSON:\n"
            "import json\n\n"
            'payload = json.loads(raw_bytes.decode("utf-8"))'
        ),
        "verify_en": (
            "Replace pickle.load/loads with JSON or a strict schema validator, verify that "
            "unvalidated bytes are rejected, and re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Zastąp pickle.load/loads formatem danych (np. JSON) z walidacją schematu "
            "i zweryfikuj brak ostrzeżenia PY003 przez `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Static AST check does not establish whether the pickle source is trusted local "
            "data or unvalidated external input."
        ),
        "limits_pl": (
            "Analiza AST nie ustala, czy strumień pickle pochodzi z zaufanego pliku lokalnego, "
            "czy z niezaufanego wejścia zewnętrznego."
        ),
    },
    "PY004": {
        "category": "tls_verification",
        "title_en": "TLS certificate verification disabled (verify=False)",
        "title_pl": "Wyłączona weryfikacja certyfikatu TLS (verify=False)",
        "mechanism_en": (
            "Passing verify=False to a requests HTTP call disables X.509 certificate chain and "
            "hostname verification, allowing any self-signed or spoofed certificate."
        ),
        "mechanism_pl": (
            "Przekazanie verify=False w bibliotece requests wyłącza weryfikację łańcucha "
            "certyfikatów X.509 oraz nazwy hosta serwera."
        ),
        "consequences_en": (
            "An active network attacker on the path can intercept or modify HTTPS traffic "
            "(man-in-the-middle), exposing credentials, tokens, or response payloads."
        ),
        "consequences_pl": (
            "Podatność na atak pośrednika (MITM) w sieci — przechwycenie lub modyfikacja "
            "ruchu HTTPS, w tym tokenów i danych uwierzytelniających."
        ),
        "example": (
            "# Keep TLS verification enabled (default) or specify a CA bundle path:\n"
            "import requests\n\n"
            "response = requests.get(url, verify=True, timeout=10)"
        ),
        "verify_en": (
            "Remove verify=False (or point verify to a pinned CA certificate bundle) and "
            "re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Usuń parametr verify=False (lub wskaż zaufany plik CA bundle) i ponownie "
            "uruchom `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Inspects literal verify=False keyword arguments on requests.* calls; custom "
            "transport adapters or environment variables are not evaluated."
        ),
        "limits_pl": (
            "Wykrywa wyłącznie literalny argument verify=False w wywołaniach requests.*; "
            "niestandardowe adaptery i zmienne środowiskowe nie są analizowane."
        ),
    },
    "PY005": {
        "category": "command_injection",
        "title_en": "Operating-system shell execution API (os.system / os.popen)",
        "title_pl": "Wywołanie powłoki systemowej (os.system / os.popen)",
        "mechanism_en": (
            "os.system and os.popen always invoke the underlying system shell to interpret "
            "a single command string."
        ),
        "mechanism_pl": (
            "Funkcje os.system oraz os.popen zawsze uruchamiają powłokę systemową do "
            "zinterpretowania przekazanego łańcucha znaków."
        ),
        "consequences_en": (
            "Shell command injection if unvalidated data is concatenated into the command, "
            "or unintended behavior when file paths contain spaces or shell metacharacters."
        ),
        "consequences_pl": (
            "Wstrzyknięcie poleceń powłoki przy łączeniu niezaufanych danych lub błędne "
            "działanie dla ścieżek zawierających spacje i znaki specjalne."
        ),
        "example": (
            "import subprocess\n\n"
            'subprocess.run(["ls", "-la", target_dir], shell=False, check=True)'
        ),
        "verify_en": (
            "Replace os.system/os.popen with subprocess.run([...], shell=False) and re-run "
            "`ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Zastąp os.system/os.popen wywołaniem subprocess.run([...], shell=False) "
            "i zweryfikuj zmianę poleceniem `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Presence of os.system/os.popen is a candidate observation; command provenance "
            "must be checked to determine whether unvalidated input reaches the argument."
        ),
        "limits_pl": (
            "Samo użycie os.system/os.popen jest obserwacją wymagającą weryfikacji, czy do "
            "argumentu docierają dane z zewnątrz."
        ),
    },
    "PY006": {
        "category": "filesystem_safety",
        "title_en": "Insecure temporary filename generation (tempfile.mktemp)",
        "title_pl": "Niebezpieczne generowanie nazwy pliku tymczasowego (tempfile.mktemp)",
        "mechanism_en": (
            "tempfile.mktemp() returns a filename without atomically creating the file, "
            "leaving a time-of-check to time-of-use (TOCTOU) window before the file is opened."
        ),
        "mechanism_pl": (
            "Funkcja tempfile.mktemp() zwraca jedynie ścieżkę bez atomowego utworzenia pliku, "
            "tworząc okno wyścigu (TOCTOU) pomiędzy wygenerowaniem nazwy a otwarciem pliku."
        ),
        "consequences_en": (
            "Symlink or file-precreation race conditions in shared temporary directories, "
            "potentially overwriting or exposing sensitive files."
        ),
        "consequences_pl": (
            "Podatność na wyścig (race condition) i podstawienie dowiązania symbolicznego "
            "w katalogu tymczasowym."
        ),
        "example": (
            "import tempfile\n\n"
            'with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as tmp:\n'
            "    tmp.write(data)"
        ),
        "verify_en": (
            "Use tempfile.NamedTemporaryFile(), tempfile.mkstemp(), or "
            "tempfile.TemporaryDirectory() "
            "and re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Użyj tempfile.NamedTemporaryFile(), tempfile.mkstemp() lub "
            "tempfile.TemporaryDirectory() "
            "i ponownie uruchom `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Static AST match; actual risk depends on directory permissions and how the "
            "returned path is subsequently opened."
        ),
        "limits_pl": (
            "Dopasowanie AST; faktyczne ryzyko zależy od uprawnień katalogu oraz flag użytych "
            "przy późniejszym otwieraniu pliku."
        ),
    },
    "PY007": {
        "category": "tls_verification",
        "title_en": "Unverified SSL/TLS context helper (ssl._create_unverified_context)",
        "title_pl": (
            "Utworzenie nieweryfikowanego kontekstu SSL/TLS (ssl._create_unverified_context)"
        ),
        "mechanism_en": (
            "ssl._create_unverified_context() constructs an SSLContext with certificate "
            "validation and hostname checking disabled by default."
        ),
        "mechanism_pl": (
            "Funkcja ssl._create_unverified_context() tworzy kontekst TLS z wyłączoną "
            "weryfikacją certyfikatu oraz nazwy hosta."
        ),
        "consequences_en": (
            "TLS connections using this context accept invalid or attacker-forged certificates, "
            "enabling man-in-the-middle interception."
        ),
        "consequences_pl": (
            "Połączenia TLS używające tego kontekstu akceptują sfałszowane certyfikaty, "
            "co umożliwia podsłuch i modyfikację komunikacji."
        ),
        "example": ("import ssl\n\ncontext = ssl.create_default_context()"),
        "verify_en": (
            "Replace ssl._create_unverified_context() with ssl.create_default_context() and "
            "re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Zastąp ssl._create_unverified_context() wywołaniem ssl.create_default_context() "
            "i sprawdź wynik `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Subsequent mutations to the returned SSLContext object are not "
            "tracked by the AST check."
        ),
        "limits_pl": (
            "Późniejsze modyfikacje właściwości obiektu SSLContext nie są "
            "śledzone przez analizator AST."
        ),
    },
    "PY008": {
        "category": "deserialization",
        "title_en": "Unsafe PyYAML loader allows arbitrary object instantiation",
        "title_pl": "Niebezpieczny loader PyYAML pozwalający na tworzenie dowolnych obiektów",
        "mechanism_en": (
            "Using yaml.unsafe_load or yaml.load with Loader/UnsafeLoader/CLoader permits "
            "!!python/object tags to instantiate arbitrary Python classes and call functions."
        ),
        "mechanism_pl": (
            "Wywołanie yaml.unsafe_load lub yaml.load z pełnym Loaderem pozwala znacznikom "
            "!!python/object na tworzenie instancji dowolnych klas i wywoływanie funkcji."
        ),
        "consequences_en": (
            "Remote or local code execution when parsing unvalidated YAML files or payloads."
        ),
        "consequences_pl": (
            "Zdalne lub lokalne wykonanie kodu podczas parsowania niezaufanego dokumentu YAML."
        ),
        "example": ("import yaml\n\nconfig = yaml.safe_load(raw_yaml)"),
        "verify_en": (
            "Switch to yaml.safe_load() or yaml.safe_load_all() and re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Użyj yaml.safe_load() lub yaml.safe_load_all() i ponownie uruchom "
            "`ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Checks direct PyYAML loader calls; does not verify whether the YAML input is "
            "trusted or attacker-controlled."
        ),
        "limits_pl": (
            "Sprawdza bezpośrednie wywołania PyYAML; nie weryfikuje, czy wejściowy YAML "
            "pochodzi z niezaufanego źródła."
        ),
    },
    "PY009": {
        "category": "cryptography",
        "title_en": "MD5 or SHA-1 digest used without non-security marker",
        "title_pl": "Użycie funkcji skrótu MD5 lub SHA-1 bez oznaczenia kontekstu",
        "mechanism_en": (
            "MD5 and SHA-1 suffer from practical collision attacks and are unsuitable for "
            "cryptographic signatures, collision-resistant integrity checks, or password hashing."
        ),
        "mechanism_pl": (
            "Funkcje MD5 i SHA-1 są podatne na praktyczne kolizje i nie zapewniają bezpieczeństwa "
            "w podpisach kryptograficznych, weryfikacji integralności ani haszowaniu haseł."
        ),
        "consequences_en": (
            "Hash collision forgery if used for security integrity, or rapid offline cracking "
            "if used to hash passwords or secrets."
        ),
        "consequences_pl": (
            "Możliwość wygenerowania kolizji skrótu lub szybkiego złamania skrótów haseł offline."
        ),
        "example": (
            "import hashlib\n\n"
            "digest = hashlib.sha256(payload).hexdigest()\n"
            "# Or if strictly non-cryptographic:\n"
            "# hashlib.md5(payload, usedforsecurity=False)"
        ),
        "verify_en": (
            "Use hashlib.sha256() / sha512() for integrity, Argon2/scrypt/PBKDF2 for passwords, "
            "or pass usedforsecurity=False for non-security checksums, then re-run `inspect`."
        ),
        "verify_pl": (
            "Użyj hashlib.sha256() do kontroli integralności, KDF do haseł lub jawnego "
            "usedforsecurity=False dla zwykłych sum kontrolnych, po czym uruchom `inspect`."
        ),
        "limits_en": (
            "The AST analyzer cannot infer whether the digest is used for security purposes "
            "or an ordinary non-cryptographic cache key."
        ),
        "limits_pl": (
            "Analizator AST nie rozstrzyga, czy skrót służy do celów bezpieczeństwa, czy jako "
            "zwykły nie-kryptograficzny identyfikator pomocniczy."
        ),
    },
    "PY010": {
        "category": "xss_templating",
        "title_en": "Jinja2 Environment configured without HTML autoescaping",
        "title_pl": "Środowisko Jinja2 skonfigurowane z wyłączonym autoescapingiem",
        "mechanism_en": (
            "Constructing jinja2.Environment without autoescape=True (or select_autoescape) "
            "renders template variables into HTML without escaping <, >, &, or quotes."
        ),
        "mechanism_pl": (
            "Utworzenie jinja2.Environment z autoescape=False (lub bez autoescape) powoduje "
            "wstawianie zmiennych do szablonów HTML bez kodowania znaków specjalnych."
        ),
        "consequences_en": (
            "Cross-Site Scripting (XSS) if HTML templates render user-supplied values."
        ),
        "consequences_pl": (
            "Podatność Cross-Site Scripting (XSS), jeśli szablon generuje HTML zawierający "
            "dane od użytkownika."
        ),
        "example": (
            "import jinja2\n\n"
            'env = jinja2.Environment(autoescape=jinja2.select_autoescape(["html", "xml"]))'
        ),
        "verify_en": (
            "Enable autoescape=True or jinja2.select_autoescape() on HTML environments and "
            "re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Włącz autoescape=True lub jinja2.select_autoescape() dla środowisk HTML "
            "i zweryfikuj poprawkę przez `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Does not determine whether the Jinja2 environment renders HTML for a browser "
            "or non-HTML plain text."
        ),
        "limits_pl": (
            "Nie ustala, czy środowisko Jinja2 generuje kod HTML dla "
            "przeglądarki, czy zwykły tekst."
        ),
    },
    "PY011": {
        "category": "xss_templating",
        "title_en": "Explicit markupsafe.Markup / flask.Markup trusts raw HTML",
        "title_pl": "Jawne oznaczenie treści jako bezpiecznego HTML (Markup)",
        "mechanism_en": (
            "Wrapping a string in Markup(...) marks it as already-safe HTML, bypassing "
            "subsequent template autoescaping."
        ),
        "mechanism_pl": (
            "Opakowanie tekstu w obiekt Markup(...) oznacza go jako zaufany kod HTML i wyłącza "
            "automatyczne escapowanie w szablonach."
        ),
        "consequences_en": (
            "Cross-Site Scripting (XSS) if unvalidated data is concatenated or formatted into "
            "the Markup string before escaping."
        ),
        "consequences_pl": (
            "Wstrzyknięcie skryptu (XSS) w przeglądarce, jeśli do obiektu Markup trafią "
            "nieoczyszczone dane wejściowe."
        ),
        "example": (
            "from markupsafe import Markup, escape\n\n"
            'safe_fragment = Markup("<strong>{}</strong>").format(escape(user_name))'
        ),
        "verify_en": (
            "Prefer template autoescaping or Markup.format() with escaped arguments, and "
            "re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Stosuj automatyczne escapowanie w szablonach i zweryfikuj miejsca użycia Markup."
        ),
        "limits_en": (
            "Static call check does not verify whether arguments passed to Markup() were "
            "already sanitized."
        ),
        "limits_pl": (
            "Statyczna kontrola nie weryfikuje, czy przekazany do Markup() tekst został wcześniej "
            "oczyszczony."
        ),
    },
    "PY012": {
        "category": "token_verification",
        "title_en": "JWT decoding with signature verification disabled",
        "title_pl": "Dekodowanie tokenu JWT z wyłączoną weryfikacją podpisu",
        "mechanism_en": (
            "Calling jwt.decode with verify=False or verify_signature=False parses claims "
            "from a JSON Web Token without verifying its cryptographic signature."
        ),
        "mechanism_pl": (
            "Wywołanie jwt.decode z verify=False lub verify_signature=False odczytuje "
            "zawartość tokenu JWT bez sprawdzenia podpisu kryptograficznego."
        ),
        "consequences_en": (
            "Authentication bypass and privilege escalation if unverified JWT claims are "
            "trusted for identity or authorization decisions."
        ),
        "consequences_pl": (
            "Obejście uwierzytelniania i eskalacja uprawnień, jeśli aplikacja ufa polom "
            "niezweryfikowanego tokenu JWT."
        ),
        "example": (
            'import jwt\n\nclaims = jwt.decode(token, verification_key, algorithms=["RS256"])'
        ),
        "verify_en": (
            "Enable signature verification with an explicit key and allowed algorithms list, "
            "then re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Wymuś weryfikację podpisu z jawnym kluczem i listą algorytmów (np. "
            "algorithms=['RS256']), "
            "a następnie ponownie uruchom `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Inspects literal jwt.decode options; does not determine whether a subsequent "
            "step verifies the token separately."
        ),
        "limits_pl": (
            "Analizuje literalne argumenty jwt.decode; nie sprawdza, czy podpis jest "
            "weryfikowany w osobnym kroku."
        ),
    },
    "PY013": {
        "category": "command_injection",
        "title_en": "Static data-flow candidate from HTTP request input to shell call",
        "title_pl": "Kandydat przepływu danych z żądania HTTP do wywołania powłoki",
        "mechanism_en": (
            "Bounded intra-file or cross-file static flow analysis traced a value derived from "
            "a Flask request object into an OS/subprocess shell command sink."
        ),
        "mechanism_pl": (
            "Statyczna analiza przepływu danych wykryła ścieżkę prowadzącą od danych żądania HTTP "
            "(Flask request) do wywołania powłoki systemowej."
        ),
        "consequences_en": (
            "Remote Command Injection if the HTTP request parameter is not strictly validated "
            "or constrained before reaching the shell invocation."
        ),
        "consequences_pl": (
            "Zdalne wykonanie poleceń systemowych (RCE / Command Injection), jeśli dane z żądania "
            "HTTP docierają do powłoki bez ścisłej walidacji."
        ),
        "example": (
            "# Avoid shell execution and pass validated arguments as a list:\n"
            'subprocess.run(["/usr/bin/tool", "--id", str(int(item_id))], shell=False, check=True)'
        ),
        "verify_en": (
            "Break the unvalidated flow by removing shell execution, using shell=False argument "
            "lists with strict allowlists, and re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Usuń wywołanie powłoki na rzecz listy argumentów z shell=False oraz białej listy "
            "wartości, po czym zweryfikuj brak reguły PY013 w `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Bounded static flow candidate only; custom sanitizers, framework middleware, "
            "and runtime route bindings were not executed or proven."
        ),
        "limits_pl": (
            "Kandydat ze statycznej analizy przepływu; niestandardowe funkcje walidujące "
            "oraz zachowanie w czasie wykonania nie były uruchamiane."
        ),
    },
    "PY014": {
        "category": "sql_injection",
        "title_en": "Static data-flow candidate from HTTP request input to SQLite query text",
        "title_pl": "Kandydat przepływu danych z żądania HTTP do treści zapytania SQLite",
        "mechanism_en": (
            "Bounded static flow analysis traced a value from a Flask HTTP request into "
            "dynamically constructed SQLite query text (string concatenation, f-string, or %)."
        ),
        "mechanism_pl": (
            "Statyczna analiza przepływu danych wykryła przekazywanie wartości z żądania HTTP "
            "do dynamicznie budowanego tekstu zapytania SQL (f-string, konkatenacja lub %)."
        ),
        "consequences_en": (
            "SQL Injection enabling unauthorized reading or modification of database records "
            "if request values alter the SQL syntax."
        ),
        "consequences_pl": (
            "Wstrzyknięcie SQL (SQL Injection) pozwalające na odczyt lub modyfikację danych "
            "w bazie SQLite."
        ),
        "example": (
            "# Use parameterized SQL queries instead of string formatting:\n"
            'cursor.execute("SELECT id, email FROM users WHERE username = ?", (username,))'
        ),
        "verify_en": (
            "Replace string formatting in SQL statements with bound parameters (`?` placeholders) "
            "and re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Zastąp formatowanie łańcuchów w zapytaniach SQL parametrami bindowanymi (`?`) "
            "i uruchom ponownie `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Bounded static flow candidate; does not evaluate prior type coercion or external "
            "validation middleware."
        ),
        "limits_pl": (
            "Kandydat ze statycznej analizy przepływu; nie uwzględnia zewnętrznych warstw "
            "walidacji ani rzutowania typów poza badaną ścieżką."
        ),
    },
    "possible_secret": {
        "category": "secret_exposure",
        "title_en": "Credential or private-key pattern in source/configuration file",
        "title_pl": "Wzorzec klucza prywatnego lub tokenu w pliku projektu",
        "mechanism_en": (
            "A line matched a high-confidence credential pattern (PEM private key header, "
            "AWS AKIA access key ID, GitHub personal/app token, or OpenAI API key prefix). "
            "The matched value is redacted in reports."
        ),
        "mechanism_pl": (
            "Linia pliku pasuje do wzorca poświadczeń (klucz prywatny PEM, identyfikator AWS AKIA, "
            "token GitHub lub klucz API OpenAI). Sama wartość została zamaskowana w raporcie."
        ),
        "consequences_en": (
            "Unauthorized access to cloud accounts, source repositories, or paid third-party "
            "APIs if the credential is live and committed to version control or distributed."
        ),
        "consequences_pl": (
            "Nieautoryzowany dostęp do usług chmurowych, repozytoriów lub płatnych API, jeśli "
            "klucz jest aktywny i trafił do repozytorium kodu."
        ),
        "example": (
            "import os\n\n"
            'api_key = os.environ["SERVICE_API_KEY"]  # Load from secret store / environment'
        ),
        "verify_en": (
            "Confirm whether the credential is real; if so, revoke/rotate it immediately, "
            "remove it from files and Git history, and re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Sprawdź, czy klucz jest prawdziwy; jeśli tak — unieważnij go i zrotuj u dostawcy, "
            "usuń z plików oraz historii Git i ponownie uruchom `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Regex pattern match only; does not contact any provider to test whether the key "
            "is active or synthetic."
        ),
        "limits_pl": (
            "Dopasowanie wzorca regularnego; analizator nie łączy się z dostawcą w celu "
            "sprawdzenia, czy klucz jest aktywny."
        ),
    },
    "floating_dependency": {
        "category": "dependency_risk",
        "title_en": "Unpinned wildcard or 'latest' dependency version in package.json",
        "title_pl": "Nieprzypięta wersja zależności ('*' lub 'latest') w package.json",
        "mechanism_en": (
            "The manifest specifies '*' or 'latest' instead of a deterministic version range "
            "or pinned release."
        ),
        "mechanism_pl": (
            "Plik manifestu używa '*' lub 'latest' zamiast konkretnej, "
            "zweryfikowanej wersji pakietu."
        ),
        "consequences_en": (
            "Non-reproducible builds and automatic installation of unreviewed or compromised "
            "new upstream releases during dependency resolution."
        ),
        "consequences_pl": (
            "Niepowtarzalne kompilacje oraz ryzyko automatycznego pobrania nieprzetestowanej "
            "lub przejętej wersji pakietu."
        ),
        "example": ('{\n  "dependencies": {\n    "example-pkg": "1.4.2"\n  }\n}'),
        "verify_en": (
            "Pin explicit package versions, commit the lockfile (package-lock.json), and "
            "re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Przypnij dokładne wersje pakietów, zatwierdź plik blokady (package-lock.json) "
            "i ponownie uruchom `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Checks literal '*' and 'latest' specifiers in package.json; does not resolve "
            "registries or verify installed node_modules."
        ),
        "limits_pl": (
            "Sprawdza wyłącznie deklaracje '*' i 'latest' w package.json bez "
            "odpytywania rejestru npm."
        ),
    },
    "invalid_manifest": {
        "category": "dependency_risk",
        "title_en": "Malformed or unreadable package manifest",
        "title_pl": "Uszkodzony lub niepoprawny składniowo plik manifestu zależności",
        "mechanism_en": (
            "The dependency manifest could not be parsed as valid JSON/structure, preventing "
            "complete dependency inventory and advisory checks."
        ),
        "mechanism_pl": (
            "Plik manifestu nie mógł zostać poprawnie sparsowany, co uniemożliwia pełną "
            "inwentaryzację zależności."
        ),
        "consequences_en": (
            "Vulnerable or unpinned dependencies in this manifest remain invisible to automated "
            "audits."
        ),
        "consequences_pl": (
            "Zależności zdefiniowane w uszkodzonym pliku pozostają niewidoczne dla audytu."
        ),
        "example": None,
        "verify_en": (
            "Fix the JSON/TOML syntax in the manifest file and re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Napraw składnię pliku manifestu i ponownie uruchom `ai-threat-lab inspect`."
        ),
        "limits_en": "Syntax/structure check only; no package installation was attempted.",
        "limits_pl": "Wyłącznie kontrola składni i struktury pliku bez instalacji pakietów.",
    },
    "known_dependency_advisory": {
        "category": "dependency_risk",
        "title_en": "Pinned dependency version matches a public OSV advisory",
        "title_pl": "Przypięta wersja pakietu występuje w publicznej bazie podatności OSV",
        "mechanism_en": (
            "The exact ecosystem, package name, and version recorded in a lockfile/manifest "
            "matched a vulnerability record returned by OSV."
        ),
        "mechanism_pl": (
            "Dokładna nazwa i wersja pakietu zapisana w pliku zależności pasuje do wpisu "
            "podatności w bazie OSV."
        ),
        "consequences_en": (
            "If the application calls the affected function or code path in the library, "
            "the vulnerability described in the advisory may be exploitable."
        ),
        "consequences_pl": (
            "Jeżeli aplikacja wykorzystuje podatną funkcję biblioteki, błąd bezpieczeństwa "
            "opisany w biuletynie może być możliwy do wykorzystania."
        ),
        "example": None,
        "verify_en": (
            "Review the linked OSV advisory, upgrade the package to a fixed release in the "
            "manifest/lockfile, run tests, and re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Zapoznaj się z biuletynem OSV, zaktualizuj pakiet do naprawionej wersji w pliku "
            "blokady, uruchom testy i ponownie wykonaj skan."
        ),
        "limits_en": (
            "Version match only; the analyzer did not verify whether the vulnerable function "
            "is reachable or used in your code."
        ),
        "limits_pl": (
            "Dopasowanie wyłącznie po numerze wersji; analizator nie badał, czy podatna funkcja "
            "jest faktycznie wywoływana w kodzie projektu."
        ),
    },
    "container_explicit_root": {
        "category": "container_configuration",
        "title_en": "Dockerfile explicitly sets runtime USER to root/0",
        "title_pl": "Plik Dockerfile jawnie ustawia użytkownika USER root/0",
        "mechanism_en": (
            "A USER root or USER 0 instruction configures container commands to run with "
            "UID 0 inside the container namespace."
        ),
        "mechanism_pl": (
            "Instrukcja USER root lub USER 0 powoduje uruchamianie procesów w kontenerze "
            "z uprawnieniami administratora (UID 0)."
        ),
        "consequences_en": (
            "Increases impact of any application compromise inside the container and raises "
            "container-escape risk if combined with permissive kernel capabilities."
        ),
        "consequences_pl": (
            "Zwiększa skutki przejęcia procesu w kontenerze i ułatwia eskalację uprawnień."
        ),
        "example": ("RUN groupadd -r appgroup && useradd -r -g appgroup appuser\nUSER appuser"),
        "verify_en": (
            "Add a dedicated non-root user in the final Dockerfile stage and re-run "
            "`ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Utwórz i ustaw dedykowanego użytkownika bez uprawnień root w końcowym etapie "
            "Dockerfile, po czym uruchom `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Line-by-line literal Dockerfile check; does not evaluate base-image defaults "
            "or runtime securityContext overrides."
        ),
        "limits_pl": (
            "Literalna kontrola linii Dockerfile; nie analizuje domyślnego użytkownika obrazu "
            "bazowego ani nadpisań w orchestratorze."
        ),
    },
    "container_mutable_base": {
        "category": "container_configuration",
        "title_en": "Dockerfile FROM image is not pinned by a SHA-256 digest",
        "title_pl": "Obraz bazowy FROM w Dockerfile nie ma przypiętego skrótu SHA-256",
        "mechanism_en": (
            "Container tags (such as :latest or :3.12) are mutable pointers in registries "
            "that can be overwritten with different image layers at any time."
        ),
        "mechanism_pl": (
            "Tagi obrazów (np. :latest lub :3.12) są zmiennymi wskaźnikami w rejestrze "
            "i mogą wskazywać na inną zawartość przy kolejnym budowaniu obrazu."
        ),
        "consequences_en": (
            "Unintended base image changes across builds or supply-chain exposure if an "
            "upstream tag is overwritten."
        ),
        "consequences_pl": (
            "Brak powtarzalności budowania obrazu oraz ryzyko pobrania zmodyfikowanego obrazu "
            "przy podmianie tagu w rejestrze."
        ),
        "example": (
            "FROM "
            "python:3.12-slim@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ),
        "verify_en": (
            "Pin the reviewed base image with `@sha256:<64-hex-digest>` and re-run "
            "`ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Przypnij zweryfikowany obraz bazowy przez `@sha256:<64-znaki-hex>` i ponownie "
            "uruchom `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Checks literal FROM lines; build arguments ($BASE_IMAGE) and registry contents "
            "are not resolved."
        ),
        "limits_pl": (
            "Sprawdza literalne instrukcje FROM; zmienne ARG oraz zawartość rejestru nie są "
            "pobierane."
        ),
    },
    "container_remote_add": {
        "category": "container_configuration",
        "title_en": "Dockerfile fetches remote URL directly via ADD instruction",
        "title_pl": "Instrukcja ADD w Dockerfile pobiera zasób bezpośrednio z adresu URL",
        "mechanism_en": (
            "Using ADD with an HTTP/HTTPS URL fetches remote bytes at build time without "
            "built-in cryptographic hash verification."
        ),
        "mechanism_pl": (
            "Instrukcja ADD z adresem HTTP/HTTPS pobiera plik z sieci podczas budowania obrazu "
            "bez wbudowanej weryfikacji sumy kontrolnej SHA-256."
        ),
        "consequences_en": (
            "Compromised or modified remote artifacts may be baked into the container image."
        ),
        "consequences_pl": (
            "Ryzyko wbudowania w obraz kontenera niezweryfikowanego lub podmienionego pliku."
        ),
        "example": None,
        "verify_en": (
            "Verify artifact checksums explicitly (e.g. `sha256sum -c`) or copy verified "
            "local build inputs, then re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Zweryfikuj sumę kontrolną SHA-256 pobieranego pliku lub użyj zweryfikowanych "
            "plików lokalnych (COPY), a następnie uruchom `ai-threat-lab inspect`."
        ),
        "limits_en": "Literal Dockerfile instruction check only.",
        "limits_pl": "Wyłącznie literalna kontrola instrukcji w pliku Dockerfile.",
    },
    "workflow_write_all": {
        "category": "ci_cd_configuration",
        "title_en": "GitHub Actions workflow grants write-all GITHUB_TOKEN permissions",
        "title_pl": (
            "Workflow GitHub Actions nadaje pełne uprawnienia zapisu (permissions: write-all)"
        ),
        "mechanism_en": (
            "`permissions: write-all` grants the workflow's GITHUB_TOKEN write access to "
            "repository contents, packages, releases, pull requests, and statuses."
        ),
        "mechanism_pl": (
            "Deklaracja `permissions: write-all` nadaje tokenowi GITHUB_TOKEN pełne uprawnienia "
            "zapisu do kodu repozytorium, paczek, wydań i pull requestów."
        ),
        "consequences_en": (
            "If any third-party action or script in the workflow is compromised, it can modify "
            "repository code or releases."
        ),
        "consequences_pl": (
            "W przypadku kompromitacji dowolnego kroku lub akcji zewnętrznej w workflow "
            "atakujący zyskuje możliwość modyfikacji kodu i wydań w repozytorium."
        ),
        "example": ("permissions:\n  contents: read"),
        "verify_en": (
            "Replace `permissions: write-all` with least-privilege permissions (such as "
            "`contents: read`) and re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Zastąp `permissions: write-all` minimalnymi wymaganymi uprawnieniami "
            "(np. `contents: read`) i ponownie uruchom `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Line-level workflow check; repository default token settings are not queried."
        ),
        "limits_pl": (
            "Kontrola linii pliku workflow bez odpytywania ustawień organizacji/repozytorium."
        ),
    },
    "workflow_mutable_action": {
        "category": "ci_cd_configuration",
        "title_en": (
            "GitHub Actions step uses a mutable branch/tag reference instead of a commit SHA"
        ),
        "title_pl": "Krok GitHub Actions używa zmiennego tagu/gałęzi zamiast pełnego SHA commita",
        "mechanism_en": (
            "Referencing an external action by tag (e.g. `@v4` or `@main`) allows the action "
            "maintainer or an attacker who compromises the action repository to move the tag "
            "to malicious code."
        ),
        "mechanism_pl": (
            "Odwołanie do zewnętrznej akcji przez tag lub gałąź (np. `@v4`, `@main`) pozwala "
            "na podmianę wykonywanego kodu w przypadku przejęcia repozytorium akcji."
        ),
        "consequences_en": (
            "Supply-chain code execution in CI/CD runners with access to repository tokens "
            "and secrets."
        ),
        "consequences_pl": (
            "Wykonanie nieautoryzowanego kodu w środowisku CI/CD z dostępem do sekretów i tokenu."
        ),
        "example": ("- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4"),
        "verify_en": (
            "Pin external `uses:` references to a reviewed 40-character commit SHA and "
            "re-run `ai-threat-lab inspect`."
        ),
        "verify_pl": (
            "Przypnij zewnętrzne akcje `uses:` do zweryfikowanego 40-znakowego skrótu SHA commita "
            "i ponownie uruchom `ai-threat-lab inspect`."
        ),
        "limits_en": (
            "Checks literal `uses:` lines in "
            "`.github/workflows/*.yml`; does not inspect composite sub-actions."
        ),
        "limits_pl": (
            "Sprawdza literalne linie `uses:` w "
            "`.github/workflows/*.yml` bez pobierania akcji zależnych."
        ),
    },
}


_LOC_AST_RE = re.compile(r"^(.+?):(\d+):(\d+)\s+[—-]\s+")
_LOC_LINE_RE = re.compile(r"^((?:[A-Za-z]:)?[^:\r\n]+):(\d+):\s+")
_LOC_SARIF_URI_RE = re.compile(r"\buri=([^;\s]+)")
_LOC_SARIF_LINE_RE = re.compile(r"\bstart_line=(\d+)")
_LOC_EXPLICIT_LINE_RE = re.compile(r"\bline\s+(\d+)\b")
_LOC_PREFIX_RE = re.compile(
    r"^((?:[A-Za-z]:)?[^\s:;#]+(?:\.[A-Za-z0-9_-]+|Dockerfile[^:\s#]*))(?:#|:|\s)"
)


def _extract_location(target: str, evidence: str) -> tuple[str | None, int | None, str | None]:
    """Extract file path and line number ONLY when explicitly present in evidence/target."""
    # Pattern 1: "<path>:<line>:<col> — ..." (Python AST review findings)
    match = _LOC_AST_RE.match(evidence)
    if match:
        return match.group(1), int(match.group(2)), match.group(2)
    # Pattern 2: "<path>:<line>: ..." (local_inventory secret / config_review findings)
    if not evidence.startswith(("http://", "https://")):
        match = _LOC_LINE_RE.match(evidence)
        if match:
            return match.group(1), int(match.group(2)), match.group(2)
    # Pattern 3: SARIF location "uri=<path>; start_line=<line>"
    sarif_uri = _LOC_SARIF_URI_RE.search(evidence)
    sarif_line = _LOC_SARIF_LINE_RE.search(evidence)
    if sarif_uri:
        line_val = int(sarif_line.group(1)) if sarif_line else None
        return sarif_uri.group(1), line_val, str(line_val) if line_val is not None else None
    # Pattern 4: explicit "line <N>" in evidence when target is a file path
    line_match = _LOC_EXPLICIT_LINE_RE.search(evidence)
    is_url_or_prefix = "://" in target or target.startswith(("mail-domain:", "mailbox:", "("))
    file_path = None
    if not is_url_or_prefix:
        prefix_match = _LOC_PREFIX_RE.match(evidence)
        if prefix_match:
            file_path = prefix_match.group(1)
        elif Path(target).suffix or Path(target).name.startswith("Dockerfile"):
            file_path = target
    if line_match:
        number = int(line_match.group(1))
        return file_path, number, str(number)
    return file_path, None, None


def _fallback_metadata(check: str, evidence: str, recommendation: str, language: str) -> dict:
    pl = language == "pl"
    if check.startswith("k8s_"):
        return {
            "category": "kubernetes_workload",
            "title": (
                f"Konfiguracja bezpieczeństwa zasobu Kubernetes ({check})"
                if pl
                else f"Kubernetes workload security posture ({check})"
            ),
            "mechanism": (
                "Manifest Kubernetes deklaruje ustawienie zmniejszające izolację kontenera "
                "lub nadające podwyższone uprawnienia względem węzła."
                if pl
                else "The Kubernetes manifest declares a workload setting that weakens container "
                "isolation or grants elevated host/kernel privileges."
            ),
            "consequences": (
                "Skompromitowany proces w kontenerze może uzyskać łatwiejszy dostęp do zasobów "
                "węzła, sieci hosta lub jądra systemu."
                if pl
                else "A compromised workload process may gain broader access to host resources, "
                "host networking, or kernel interfaces."
            ),
            "verify": (
                "Zaktualizuj pole securityContext / specyfikację poda w manifeście JSON i ponownie "
                "uruchom `ai-threat-lab inspect`."
                if pl
                else "Harden the pod/container securityContext in the manifest and re-run "
                "`ai-threat-lab inspect`."
            ),
            "limits": (
                "Statyczna kontrola pól pliku JSON bez połączenia z klastrem Kubernetes i bez "
                "analizy polityk admission controller."
                if pl
                else "Static JSON field check without cluster connection or admission-controller "
                "evaluation."
            ),
        }
    if check == "html_external_script_without_integrity":
        return {
            "category": "html_external_script",
            "title": (
                "Zewnętrzny skrypt JavaScript bez atrybutu integralności (SRI)"
                if pl
                else "External JavaScript script without Subresource Integrity (SRI)"
            ),
            "mechanism": (
                (
                    "Dokument HTML ładuje zewnętrzny skrypt JavaScript z innej "
                    "domeny (cross-origin) bez atrybutu `integrity`. Mechanizm "
                    "Subresource Integrity (SRI) pozwala przeglądarce zweryfikować "
                    "kryptograficzny skrót pobranego pliku przed jego wykonaniem, "
                    "gwarantując, że zasób nie został podmieniony ani "
                    "zmodyfikowany na zewnętrznym serwerze CDN bądź w tranzycie."
                )
                if pl
                else (
                    "The HTML document loads an external JavaScript script from "
                    "a third-party origin without an `integrity` attribute. "
                    "Subresource Integrity (SRI) allows browsers to verify a "
                    "cryptographic digest of fetched files before execution, "
                    "ensuring the resource has not been altered on a third-party "
                    "CDN or in transit."
                )
            ),
            "consequences": (
                (
                    "W przypadku kompromitacji zewnętrznego dostawcy CDN napastnik "
                    "mógłby wstrzyknąć złośliwy kod wykonywany w kontekście "
                    "użytkowników witryny. Ryzyko zależy od stopnia zaufania do "
                    "zewnętrznego dostawcy oraz wdrożonej polityki CSP. Wykrycie "
                    "nie oznacza ataku ani złośliwości skryptu — wskazuje na brak "
                    "kryptograficznej ochrony zasobu przed modyfikacją."
                )
                if pl
                else (
                    "If the third-party CDN or provider is compromised, an attacker "
                    "could inject malicious code executed within site visitors' origin "
                    "context. Actual risk depends on trust in the provider and CSP. "
                    "This observation does not indicate an attack or malicious content — "
                    "it identifies the lack of cryptographic tamper-resistance."
                )
            ),
            "verify": (
                (
                    "W przypadku skryptów statycznych (biblioteki JS) dodaj atrybuty "
                    '`integrity="sha384-..." crossorigin="anonymous"`. '
                    "Dla dynamicznych skryptów analitycznych lub tag managerów, które "
                    "uniemożliwiają stałe SRI, rozważ hosting lokalny na własnym "
                    "serwerze, restrykcyjną dyrektywę `script-src` w nagłówku "
                    "Content-Security-Policy (CSP) lub formalną weryfikację dostawcy."
                )
                if pl
                else (
                    'For static third-party libraries, add `integrity="sha384-..." '
                    'crossorigin="anonymous"`. For dynamic scripts or analytics tags '
                    "where static SRI is impractical, consider self-hosting, enforcing "
                    "strict `script-src` in Content-Security-Policy (CSP), or auditing "
                    "vendor trust."
                )
            ),
            "limits": (
                (
                    "Pasywna analiza statyczna HTML; nie ocenia skryptów dołączanych "
                    "dynamicznie przez kod JS w czasie wykonywania ani reputacji CDN."
                )
                if pl
                else (
                    "Passive static HTML analysis; does not inspect dynamic runtime script "
                    "injection or assess CDN domain reputation."
                )
            ),
        }
    if check == "html_password_form_get":
        return {
            "category": "html_credential_transport",
            "title": (
                "Formularz hasła przesyłany metodą GET"
                if pl
                else "Password form submitted via GET method"
            ),
            "mechanism": (
                (
                    "Formularz zawiera pole hasła, lecz deklaruje metodę GET. "
                    "Powoduje to przekazywanie poświadczeń w parametrach adresu URL."
                )
                if pl
                else (
                    "The form contains a password input but declares method GET, "
                    "appending credentials to the URL query string."
                )
            ),
            "consequences": (
                (
                    "Poświadczenia mogą wyciekać do historii przeglądarki, "
                    "logów serwera proxy i nagłówków Referer."
                )
                if pl
                else (
                    "Credentials may leak into browser history, web server access "
                    "logs, proxy caches, and Referer headers."
                )
            ),
            "verify": (
                (
                    'Zmień metodę formularza na `method="post"` i upewnij się, '
                    "że przesyłanie odbywa się przez HTTPS."
                )
                if pl
                else 'Update the form declaration to `method="post"` over secure HTTPS.'
            ),
            "limits": (
                "Statyczna analiza deklaracji formularza w dokumencie HTML."
                if pl
                else "Static HTML form declaration inspection without submitting data."
            ),
        }
    if check == "html_password_form_http":
        return {
            "category": "html_credential_transport",
            "title": (
                "Formularz hasła przesyłany przez nieszyfrowany protokół HTTP"
                if pl
                else "Password form submitted over unencrypted HTTP"
            ),
            "mechanism": (
                "Formularz hasła przesyła dane na adres HTTP pozbawiony szyfrowania TLS."
                if pl
                else (
                    "The password form submits credentials to an unencrypted cleartext "
                    "HTTP destination."
                )
            ),
            "consequences": (
                (
                    "Poświadczenia logowania są przesyłane otwartym tekstem i mogą "
                    "zostać przechwycone przez podsłuch w sieci."
                )
                if pl
                else (
                    "Credentials travel in plaintext across the network, vulnerable "
                    "to eavesdropping and on-path interception."
                )
            ),
            "verify": (
                (
                    "Skonfiguruj przesyłanie formularza wyłącznie na zweryfikowany "
                    "adres HTTPS docelowego serwera."
                )
                if pl
                else "Configure form action exclusively to authenticated HTTPS endpoints."
            ),
            "limits": (
                "Pasywne parsowanie znacznika form w pliku HTML."
                if pl
                else "Passive parsing of form action attributes in static HTML."
            ),
        }
    if check == "html_password_form_cross_origin":
        return {
            "category": "html_credential_transport",
            "title": (
                "Formularz hasła przesyłany do innego pochodzenia (Cross-Origin)"
                if pl
                else "Password form submitted to a different origin (Cross-Origin)"
            ),
            "mechanism": (
                (
                    "Formularz hasła przesyła poświadczenia do innej domeny "
                    "lub portu niż bieżący dokument."
                )
                if pl
                else (
                    "The password form submits credentials to a different origin "
                    "than the hosting document."
                )
            ),
            "consequences": (
                (
                    "Ryzyko przekazania poświadczeń zewnętrznemu podmiotowi "
                    "w przypadku nieautoryzowanych modyfikacji."
                )
                if pl
                else (
                    "Risk of sending credentials to external entities if page markup is modified."
                )
            ),
            "verify": (
                (
                    "Zweryfikuj odbiorcę formularza i upewnij się, "
                    "że przesyłanie cross-origin jest zamierzone i bezpieczne."
                )
                if pl
                else (
                    "Verify the credential recipient origin and ensure cross-origin "
                    "submission is intended and secured."
                )
            ),
            "limits": (
                ("Porównanie schematu, hosta i portu adresu docelowego z adresem dokumentu.")
                if pl
                else ("Comparison of destination scheme, host, and port against document origin.")
            ),
        }
    if check == "html_mixed_active_content":
        return {
            "category": "html_mixed_content",
            "title": (
                "Mieszana zawartość aktywna (zasób HTTP na stronie HTTPS)"
                if pl
                else "Mixed active content (HTTP resource inside HTTPS document)"
            ),
            "mechanism": (
                (
                    "Bezpieczny dokument HTTPS odwołuje się do aktywnego zasobu "
                    "(skrypt, ramka) przez nieszyfrowany protokół HTTP."
                )
                if pl
                else (
                    "A secure HTTPS document references active resources "
                    "(scripts, iframes) via unencrypted HTTP."
                )
            ),
            "consequences": (
                (
                    "Zasób zostanie zablokowany przez przeglądarkę, co może zaburzyć "
                    "działanie strony; brak blokady grozi wstrzyknięciem kodu."
                )
                if pl
                else (
                    "Modern browsers block active mixed content, breaking features; "
                    "unblocked resources allow on-path injection."
                )
            ),
            "verify": (
                "Zmień adres zasobu na HTTPS lub hostuj go lokalnie."
                if pl
                else "Update resource URL to HTTPS or host it locally."
            ),
            "limits": (
                ("Pasywna statyczna analiza znaczników HTML bez wykonywania zapytań sieciowych.")
                if pl
                else "Passive static HTML markup inspection without issuing network requests."
            ),
        }
    if check.startswith(("html_", "message_html_")):
        return {
            "category": "html_general_resource",
            "title": (
                f"Obserwacja elementu HTML ({check})"
                if pl
                else f"HTML element observation ({check})"
            ),
            "mechanism": (
                (f"Analizator wykrył wzorzec strukturalny w dokumencie HTML dla reguły `{check}`.")
                if pl
                else f"The analyzer identified an HTML structural pattern for check `{check}`."
            ),
            "consequences": (
                (
                    "Wymaga przeglądu kontekstowego pod kątem bezpieczeństwa "
                    "transportu i integralności."
                )
                if pl
                else (
                    "Requires contextual review regarding transport security "
                    "and resource integrity."
                )
            ),
            "verify": (
                (
                    "Przejrzyj zidentyfikowany element HTML i upewnij się, "
                    "że zasoby są zabezpieczone."
                )
                if pl
                else "Inspect the identified HTML element and verify resource security."
            ),
            "limits": (
                ("Pasywne parsowanie zapisanego HTML bez uruchamiania przeglądarki i JavaScriptu.")
                if pl
                else (
                    "Passive parsing of saved HTML without browser rendering "
                    "or JavaScript execution."
                )
            ),
        }
    if (
        check.startswith(("missing_", "weak_", "csp_", "cookie_", "referrer_", "permissions_"))
        or "header" in check
        or "policy" in check.lower()
    ):
        return {
            "category": "web_transport_headers",
            "title": (
                f"Obserwacja nagłówka lub polityki bezpieczeństwa HTTP ({check})"
                if pl
                else f"HTTP security header or policy observation ({check})"
            ),
            "mechanism": (
                "Odpowiedź HTTP nie zawiera zalecanego nagłówka ochronnego lub zawiera dyrektywę "
                "osłabiającą mechanizmy izolacji przeglądarki."
                if pl
                else "The HTTP response omits a defense-in-depth security header or includes a "
                "directive that weakens browser isolation controls."
            ),
            "consequences": (
                "Osłabiona ochrona przeglądarki przed atakami typu XSS, "
                "clickjacking, downgrade TLS "
                "lub wyciekiem ciasteczek sesyjnych."
                if pl
                else "Reduced browser defense-in-depth against XSS, framing/clickjacking, TLS "
                "downgrade, or cookie exposure."
            ),
            "verify": (
                "Skonfiguruj odpowiedni nagłówek HTTP na serwerze/reverse proxy i zweryfikuj "
                "zapis odpowiedzi poleceniem `ai-threat-lab review-headers` lub `inspect`."
                if pl
                else "Configure the response header in your web server or reverse proxy and "
                "re-verify with `ai-threat-lab review-headers` or `inspect`."
            ),
            "limits": (
                "Kontrola pojedynczego zapisu nagłówków; nie weryfikuje zachowania przeglądarki "
                "ani logiki aplikacji."
                if pl
                else "Single response-header inspection; does not verify browser enforcement or "
                "application logic."
            ),
        }
    if check.startswith(
        (
            "message_",
            "reported_authentication",
            "authentication_header",
            "different_reply_to",
        )
    ):
        return {
            "category": "email_content_attachment",
            "title": (
                f"Obserwacja bezpieczeństwa w zapisanej wiadomości e-mail ({check})"
                if pl
                else f"Saved email message security observation ({check})"
            ),
            "mechanism": (
                "Wiadomość EML zawiera wskaźnik wymagający ostrożności (np. rozbieżny Reply-To, "
                "błąd SPF/DKIM/DMARC w nagłówku, podejrzany link lub załącznik wykonywalny)."
                if pl
                else "The saved EML message contains a header, link, or attachment indicator "
                "commonly associated with spoofing or phishing delivery."
            ),
            "consequences": (
                "Ryzyko wprowadzenia odbiorcy w błąd (phishing) lub uruchomienia niebezpiecznego "
                "załącznika w przypadku braku weryfikacji nadawcy."
                if pl
                else "Potential recipient deception (phishing) or execution of "
                "unvalidated attachment "
                "content if treated as authentic."
            ),
            "verify": (
                "Zweryfikuj autentyczność nadawcy niezależnym kanałem oraz logi "
                "serwera pocztowego; "
                "nie otwieraj ani nie uruchamiaj podejrzanych załączników."
                if pl
                else "Verify sender authenticity out-of-band and check trusted mail-server logs; "
                "do not execute or open unvalidated attachments."
            ),
            "limits": (
                "Analiza offline zapisanego pliku EML bez sprawdzania DNS/podpisów "
                "kryptograficznych "
                "DKIM i bez otwierania linków."
                if pl
                else "Offline EML parsing only; cryptographic DKIM signatures, live DNS records, "
                "and link targets were not queried."
            ),
        }
    if check.startswith(("pe_", "elf_", "zip_", "binary_", "office_")):
        return {
            "category": "binary_archive_structure",
            "title": (
                f"Obserwacja struktury pliku binarnego, archiwum lub pakietu Office ({check})"
                if pl
                else f"Binary, archive, or Office package structural observation ({check})"
            ),
            "mechanism": (
                "Statyczna analiza nagłówków wykryła cechę strukturalną (np. brak flagi ochronnej "
                "PE/ELF, ścieżkę ucieczki w ZIP lub deklarację makra/relacji zewnętrznej w Office)."
                if pl
                else "Bounded static header/metadata inspection identified a structural attribute "
                "(e.g., missing binary hardening flag, unsafe archive entry path, or "
                "Office macro/external relationship)."
            ),
            "consequences": (
                "Zależy od sposobu użycia pliku: np. nadpisanie plików poza katalogiem docelowym "
                "(Zip Slip), wykonanie makra przy otwarciu dokumentu lub brak "
                "ochrony pamięci procesu."
                if pl
                else "Depends on how the artifact is processed: path traversal on extraction, "
                "macro/external resource activation in Office, or reduced binary "
                "exploit mitigation."
            ),
            "verify": (
                "Sprawdź pochodzenie pliku, flagi kompilacji lub procedurę rozpakowywania archiwum "
                "i ponownie wykonaj analizę statyczną."
                if pl
                else "Verify artifact provenance, compiler hardening flags, or archive extraction "
                "guards and re-run the static check."
            ),
            "limits": (
                "Wyłącznie statyczny odczyt nagłówków i metadanych w pamięci; plik nie był "
                "uruchamiany, dekompresowany na dysk ani skanowany antywirusem."
                if pl
                else "Bounded static header/metadata inspection only; no "
                "execution, disk extraction, "
                "disassembly, or malware signature scanning was performed."
            ),
        }
    if check.startswith("auth_"):
        return {
            "category": "authentication_telemetry",
            "title": (
                f"Wzorzec anomalii logowania w zapisanym dzienniku ({check})"
                if pl
                else f"Authentication log pattern observation ({check})"
            ),
            "mechanism": (
                "W zadanym oknie czasowym odnotowano serię nieudanych logowań, prób na wiele kont "
                "(password spraying), rozproszone źródła lub sukces po serii błędów."
                if pl
                else "Within the configured time window, saved login events "
                "matched a repeated-failure, "
                "password-spray, distributed-source, or success-after-failure pattern."
            ),
            "consequences": (
                "Wskazuje na potencjalne próby odgadywania haseł (brute-force / "
                "credential stuffing) "
                "lub możliwe przejęcie konta po wcześniejszych nieudanych próbach."
                if pl
                else "Indicates potential brute-force or credential-stuffing activity, or a "
                "session that requires review after prior authentication failures."
            ),
            "verify": (
                "Przejrzyj pełne logi uwierzytelniania, wymuś MFA/reset hasła w razie potrzeby "
                "i ponownie przeanalizuj nowy eksport logów."
                if pl
                else "Inspect full authentication telemetry and session logs, enforce MFA/password "
                "rotation if warranted, and re-run the log review on subsequent captures."
            ),
            "limits": (
                "Analiza wzorców w zapisanym pliku JSONL; nie dowodzi przejęcia konta ani "
                "skuteczności blokad po stronie serwera."
                if pl
                else "Offline log-window pattern match only; does not prove account compromise."
            ),
        }
    return {
        "category": "general_observation",
        "title": (
            f"Obserwacja audytowa ({check})" if pl else f"Security audit observation ({check})"
        ),
        "mechanism": (
            f"Analizator zgłosił obserwację dla reguły `{check}` na podstawie dowodu: {evidence}"
            if pl
            else f"The analyzer recorded an observation for check `{check}` based on: {evidence}"
        ),
        "consequences": (
            "Wymaga przeglądu przez inżyniera w celu oceny wpływu w kontekście docelowego systemu."
            if pl
            else "Requires human engineering review to determine impact in the target context."
        ),
        "verify": (
            f"Zastosuj zalecenie ({recommendation}) i ponownie uruchom kontrolę `ai-threat-lab`."
            if pl
            else f"Apply the recommended action ({recommendation}) and re-run `ai-threat-lab`."
        ),
        "limits": (
            "Statyczna obserwacja częściowa; nie stanowi potwierdzonej "
            "podatności bez weryfikacji kontekstu."
            if pl
            else "Partial static observation; not a confirmed vulnerability "
            "without context verification."
        ),
    }


def describe_finding(
    finding: dict | AssessmentFinding | CodeFinding,
    *,
    target: str | None = None,
    language: str = "en",
) -> DetailedFinding:
    """Build a complete DetailedFinding without inventing line numbers or overclaiming status."""
    validate_report_language(language)
    pl = language == "pl"

    if isinstance(finding, CodeFinding):
        rule_code = finding.rule_id
        status = "candidate"
        resolved_target = target or "<snippet>"
        evidence = f"{resolved_target}:{finding.line}:{finding.column} — {finding.title}"
        if finding.rule_id in ("PY013", "PY014"):
            evidence += f". {finding.rationale}"
        recommendation = finding.recommendation
        canonical = json.dumps(
            {
                "target": resolved_target,
                "check": rule_code,
                "status": status,
                "evidence": evidence,
                "recommendation": recommendation,
            },
            sort_keys=True,
        )
        identifier = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        priority = PRIORITIES.get(rule_code, "P3")
        file_path = None if resolved_target == "<snippet>" else resolved_target
        line_number = finding.line
        line_range = str(finding.line)
    elif isinstance(finding, AssessmentFinding):
        rule_code = finding.check
        status = finding.status
        resolved_target = target or "(unspecified target)"
        evidence = finding.evidence
        recommendation = finding.recommendation
        canonical = json.dumps(
            {
                "target": resolved_target,
                "check": rule_code,
                "status": status,
                "evidence": evidence,
                "recommendation": recommendation,
            },
            sort_keys=True,
        )
        identifier = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        priority = PRIORITIES.get(rule_code, "P3")
        file_path, line_number, line_range = _extract_location(resolved_target, evidence)
    elif isinstance(finding, dict):
        rule_code = str(
            finding.get("check")
            or finding.get("rule_id")
            or finding.get("rule_code")
            or "unspecified"
        )
        status = str(finding.get("status", "candidate"))
        resolved_target = str(finding.get("target") or target or "(unspecified target)")
        evidence = str(finding.get("evidence", ""))
        recommendation = str(finding.get("recommendation", ""))
        identifier = finding.get("id") or finding.get("evidence_id")
        if not identifier:
            canonical = json.dumps(
                {
                    "target": resolved_target,
                    "check": rule_code,
                    "status": status,
                    "evidence": evidence,
                    "recommendation": recommendation,
                },
                sort_keys=True,
            )
            identifier = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        priority = str(finding.get("triage_priority") or PRIORITIES.get(rule_code, "P3"))
        file_path, line_number, line_range = _extract_location(resolved_target, evidence)
    else:
        raise ValidationError("Unsupported finding type for detailed description")

    entry = _RULE_CATALOG.get(rule_code)
    if entry is not None:
        category = str(entry["category"])
        title = str(entry["title_pl" if pl else "title_en"])
        mechanism = str(entry["mechanism_pl" if pl else "mechanism_en"])
        consequences = str(entry["consequences_pl" if pl else "consequences_en"])
        code_example = entry["example"]
        verification_steps = str(entry["verify_pl" if pl else "verify_en"])
        analysis_limitations = str(entry["limits_pl" if pl else "limits_en"])
    else:
        fallback = _fallback_metadata(rule_code, evidence, recommendation, language)
        category = fallback["category"]
        title = fallback["title"]
        mechanism = fallback["mechanism"]
        consequences = fallback["consequences"]
        code_example = None
        verification_steps = fallback["verify"]
        analysis_limitations = fallback["limits"]

    location_label = file_path or resolved_target
    if line_number is not None:
        location_label = (
            f"{location_label} (line {line_number})"
            if not pl
            else f"{location_label} (linia {line_number})"
        )
    what_was_detected = (
        f"{title} — lokalizacja: {location_label}. Dowód: {evidence}"
        if pl
        else f"{title} — location: {location_label}. Evidence: {evidence}"
    )

    return DetailedFinding(
        id=str(identifier),
        rule_code=rule_code,
        title=title,
        threat_category=category,
        target=resolved_target,
        file_path=file_path,
        line_number=line_number,
        line_range=line_range,
        evidence=evidence,
        what_was_detected=what_was_detected,
        mechanism=mechanism,
        consequences=consequences,
        recommendation=recommendation,
        code_example=code_example,
        verification_steps=verification_steps,
        analysis_limitations=analysis_limitations,
        confirmation_status=status,
        triage_priority=priority,
        language=language,
    )


def detailed_findings(
    source: dict | AssessmentResult | CodeReviewResult,
    *,
    language: str = "en",
) -> tuple[DetailedFinding, ...]:
    """Convert any report dict, AssessmentResult, or CodeReviewResult into DetailedFinding items."""
    validate_report_language(language)
    if isinstance(source, CodeReviewResult):
        return tuple(
            describe_finding(item, target=source.filename, language=language)
            for item in source.findings
        )
    if isinstance(source, AssessmentResult):
        return tuple(
            describe_finding(item, target=source.target, language=language)
            for item in source.findings
        )
    if isinstance(source, dict) and isinstance(source.get("findings"), list):
        default_target = source.get("target")
        return tuple(
            describe_finding(item, target=default_target, language=language)
            for item in source["findings"]
        )
    raise ValidationError("Source must be a report dict, AssessmentResult, or CodeReviewResult")
