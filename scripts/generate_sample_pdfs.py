"""Generate reproducible synthetic PDF examples through the real offline scanner."""

import argparse
import tempfile
from pathlib import Path

from ai_threat_lab.gui_api import export_audit_report, run_audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="audit samples ") as folder:
        root = Path(folder)
        source = root / "fictional.py"
        source.write_text("import pickle\npickle.loads(untrusted_bytes)\n", encoding="utf-8")
        run = root / "run"
        run_audit(source, run)
        # No model calls, invented AI findings or implicit source reopening.
        for language in ("pl", "en"):
            export_audit_report(run, args.output_dir / f"sample_audit_{language}.pdf",
                                format="pdf", language=language)


if __name__ == "__main__":
    main()
