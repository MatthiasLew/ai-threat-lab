"""Guided console client of the existing command/service contracts."""

from .console_workflows import history_menu, training_menu
from .models import ValidationError
from .tool_plan import plan_target

MENU = """
AI Threat Lab
1. Plan and inspect a target with prepared tools
2. Read a saved assessment or scan summary
3. Preview evidence and cost for optional AI interpretation
4. Explore a fictional risk scenario
5. Check local configuration and remaining API setup
6. Show capabilities and limits
7. Prepare, approve and run local training
8. Browse history, compare, export or scan a local batch
9. Review multiple pages within an approved website path
0. Exit
"""


def ask(label, *, required=True):
    value = input(label).strip()
    if len(value) > 4096 or any(ord(c) < 32 for c in value):
        raise ValidationError("Enter at most 4096 characters without terminal controls")
    if required and not value:
        raise ValidationError("A value is required; choose 0 in the main menu to exit")
    return value


def run_console(run):
    """`run` receives argument lists, never shell strings or model-generated commands."""
    while True:
        try:
            print(MENU)
            choice = ask("Choose 0–9: ")
            if choice == "0":
                return 0
            if choice == "1":
                target = ask("Target path, HTTPS URL, mail-domain:domain or mailbox:address: ")
                plan = plan_target(target)
                print("Prepared checks:")
                for tool in plan["tools"]:
                    print(f'  {tool["purpose"]}\n  Limits: {tool["limit"]}')
                for disclosure in plan["data_disclosure"]:
                    print("Data disclosure: " + disclosure)
                for requirement in plan["setup_requirements"]:
                    print("Setup: " + requirement)
                arguments = ["inspect", target]
                if plan["network_destinations"]:
                    print("Network destinations: " + ", ".join(plan["network_destinations"]))
                    if ask("Allow these read-only network requests? [y/N]: ",
                           required=False).lower() != "y":
                        print("Collection cancelled. No network request was made.")
                        continue
                    arguments += ["--network", "--allow-host", plan["approval_host"]]
                output = ask("New output directory for evidence and reports: ")
                arguments += ["--output-dir", output]
                if ask("Run the displayed checks? [y/N]: ", required=False).lower() != "y":
                    print("Collection cancelled.")
                    continue
                code = run(arguments)
            elif choice == "2":
                code = run(["brief", ask("Saved assessment/report file or scan/batch directory: ")])
            elif choice == "3":
                evidence = ask("Saved assessment/report file or scan/batch directory: ")
                config = ask("AI configuration file (model, prices and limits; no key): ")
                output = ask("New preview JSON file: ")
                code = run(["ai-prepare", evidence, "--ai-config", config,
                            "--structured", "--split", "--output", output])
                if code == 0:
                    print("Preview saved. No key was read and no API call was made. "
                          "Use ai-review only after reviewing the preview "
                          "and configuring an account.")
            elif choice == "4":
                code = run(["interactive"])
            elif choice == "5":
                config = ask("AI configuration file (Enter to check installation only): ",
                             required=False)
                code = run(["setup-check", *(["--ai-config", config] if config else [])])
            elif choice == "6":
                code = run(["readiness"])
            elif choice == "7":
                code = training_menu(run, ask)
            elif choice == "8":
                code = history_menu(run, ask)
            elif choice == "9":
                from urllib.parse import urlsplit

                from .site_review import canonical_url

                target = canonical_url(ask("Start HTTPS URL (no query or credentials): "))
                prefix = ask("Approved path prefix ending in /: ")
                output = ask("New combined JSON report: ")
                print("Up to 10 GET requests, depth 2, within this host and path. "
                      "No cookies, login, forms or redirects. "
                      "GET can have effects on incorrectly designed applications.")
                if ask("Allow these requests? [y/N]: ", required=False).lower() != "y":
                    continue
                code = run(["review-site", target, "--network", "--allow-host",
                            urlsplit(target).hostname, "--path-prefix", prefix,
                            "--output", output])
            else:
                print("Choose a number from 0 to 9.")
                continue
            if code:
                print(f"Operation returned status {code}; review the diagnostic above.")
        except ValidationError as exc:
            print(f"Input problem: {exc}")
        except OSError:
            print("Cannot read the selected local file. Check its path and permissions.")
        except (EOFError, KeyboardInterrupt):
            print("\nConsole closed. No further operation was started.")
            return 0
