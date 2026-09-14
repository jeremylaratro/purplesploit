"""Command-line entry point for PurpleSploit report generation."""

import argparse

from .generator import ReportGenerator


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a PurpleSploit assessment report")
    parser.add_argument(
        "--format", choices=("json", "html", "markdown", "pdf", "xlsx"),
        default="html", help="Output format (default: html)",
    )
    parser.add_argument("--output", help="Output path; defaults to the report configuration")
    parser.add_argument("--findings", help="Optional JSON file containing findings")
    args = parser.parse_args()

    generator = ReportGenerator()
    if args.findings:
        generator.load_findings_from_json(args.findings)
    output = generator.generate(args.format, args.output)
    print(output)


if __name__ == "__main__":
    main()
