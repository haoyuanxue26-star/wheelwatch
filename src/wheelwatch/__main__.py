"""Command-line interface: JSON on stdout, stable exit codes."""
import argparse
import json

from .audit import Limits, audit


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect a wheel offline, without executing package code")
    parser.add_argument("wheel")
    parser.add_argument("--fail-on", choices=("error", "warning"), default="error")
    defaults = Limits()
    for name in ("archive_bytes", "total_bytes", "file_bytes", "entries", "record_bytes"):
        parser.add_argument("--max-" + name.replace("_", "-"), type=int, default=getattr(defaults, name))
    args = parser.parse_args()
    limits = Limits(**{name: getattr(args, "max_" + name) for name in defaults.__dataclass_fields__})
    report = audit(args.wheel, limits)
    print(json.dumps(report.to_dict(), ensure_ascii=True, indent=2))
    return int(not report.ok or (args.fail_on == "warning" and any(f.severity == "warning" for f in report.findings)))


if __name__ == "__main__":
    raise SystemExit(main())
