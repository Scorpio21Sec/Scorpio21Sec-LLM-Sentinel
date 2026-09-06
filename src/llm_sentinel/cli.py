"""
Command-line interface for LLM Sentinel.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import risk_level, risk_score, scan_text


def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="llm-sentinel",
        description="Defensive LLM application security scanner.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan text supplied directly on the command line.",
    )

    scan_parser.add_argument(
        "text",
        help="Text to scan.",
    )

    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Return JSON output.",
    )

    file_parser = subparsers.add_parser(
        "scan-file",
        help="Scan a text or JSON file.",
    )

    file_parser.add_argument(
        "path",
        help="Path to the file.",
    )

    file_parser.add_argument(
        "--json",
        action="store_true",
        help="Return JSON output.",
    )

    return parser


def make_report(text: str) -> dict:

    findings = scan_text(text)

    score = risk_score(findings)

    return {
        "tool": "LLM Sentinel",
        "version": "0.1.0",
        "risk_score": score,
        "risk_level": risk_level(score),
        "finding_count": len(findings),
        "findings": [
            finding.to_dict()
            for finding in findings
        ],
    }


def print_text_report(report: dict) -> None:

    print("=" * 60)
    print("LLM SENTINEL SECURITY REPORT")
    print("=" * 60)

    print(f"Risk Score : {report['risk_score']}/100")
    print(f"Risk Level : {report['risk_level']}")
    print(f"Findings   : {report['finding_count']}")

    print()

    if not report["findings"]:
        print("No known security indicators detected.")
        return

    for finding in report["findings"]:

        print("-" * 60)

        print(
            f"[{finding['severity']}] "
            f"{finding['rule_id']} - "
            f"{finding['title']}"
        )

        print(f"Category: {finding['category']}")

        print(f"Evidence: {finding['evidence']}")

        print(
            f"Recommendation: "
            f"{finding['recommendation']}"
        )


def read_file(path: str) -> str:

    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    if not file_path.is_file():
        raise ValueError(
            f"Not a regular file: {file_path}"
        )

    return file_path.read_text(
        encoding="utf-8",
        errors="replace",
    )


def main() -> int:

    parser = build_parser()

    args = parser.parse_args()

    try:

        if args.command == "scan":

            text = args.text

        elif args.command == "scan-file":

            text = read_file(args.path)

        else:

            parser.error("Unknown command")

            return 2

        report = make_report(text)

        if args.json:

            print(
                json.dumps(
                    report,
                    indent=2,
                )
            )

        else:

            print_text_report(report)

        return 0

    except Exception as exc:

        print(
            f"Error: {exc}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())