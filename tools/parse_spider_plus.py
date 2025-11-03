#!/usr/bin/env python3
"""
Parse nxc spider_plus output and display discovered files with shares and sizes.
"""
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple


def parse_bytes(size_str: str) -> float:
    """Convert size string (e.g., '1.6 KB', '23 B') to bytes for sorting."""
    units = {
        'B': 1,
        'KB': 1024,
        'MB': 1024**2,
        'GB': 1024**3,
        'TB': 1024**4
    }

    parts = size_str.strip().split()
    if len(parts) != 2:
        return 0

    try:
        value = float(parts[0])
        unit = parts[1].upper()
        return value * units.get(unit, 1)
    except (ValueError, KeyError):
        return 0


def parse_spider_plus_file(json_path: str) -> List[Tuple[str, str, str]]:
    """
    Parse a spider_plus JSON file and return list of (share, filename, size).

    Args:
        json_path: Path to the JSON file

    Returns:
        List of tuples containing (share_name, file_path, size)
    """
    results = []

    try:
        with open(json_path, 'r') as f:
            data = json.load(f)

        for share_name, files in data.items():
            if not files:  # Skip empty shares
                continue

            for file_path, metadata in files.items():
                size = metadata.get('size', 'Unknown')
                results.append((share_name, file_path, size))

    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error reading {json_path}: {e}", file=sys.stderr)
        return []

    return results


def print_results(results: List[Tuple[str, str, str]], ip: str = None, sort_by: str = 'share'):
    """
    Print the parsed results in a formatted table.

    Args:
        results: List of (share_name, file_path, size) tuples
        ip: Optional IP address for display
        sort_by: Sort by 'share', 'size', or 'name'
    """
    if not results:
        print("No files found.")
        return

    # Sort results
    if sort_by == 'size':
        results.sort(key=lambda x: parse_bytes(x[2]), reverse=True)
    elif sort_by == 'name':
        results.sort(key=lambda x: (x[0], x[1]))
    else:  # sort by share (default)
        results.sort(key=lambda x: (x[0], x[1]))

    # Print header
    if ip:
        print(f"\n{'='*80}")
        print(f"Spider Plus Results for {ip}")
        print(f"{'='*80}")

    print(f"\n{'Share':<20} {'Size':<12} {'File Path'}")
    print(f"{'-'*20} {'-'*12} {'-'*45}")

    # Print results
    for share, filepath, size in results:
        print(f"{share:<20} {size:<12} {filepath}")

    # Print summary
    print(f"\n{'='*80}")
    print(f"Total files found: {len(results)}")

    # Count files per share
    shares = {}
    for share, _, _ in results:
        shares[share] = shares.get(share, 0) + 1

    print(f"Files per share:")
    for share, count in sorted(shares.items()):
        print(f"  {share}: {count} files")


def main():
    """Main function to parse spider_plus output."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Parse nxc spider_plus output and display discovered files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Parse a specific IP's results
  %(prog)s 192.168.1.100

  # Parse all available results
  %(prog)s --all

  # Sort by file size (largest first)
  %(prog)s 192.168.1.100 --sort size

  # Sort by filename
  %(prog)s 192.168.1.100 --sort name
        """
    )

    parser.add_argument('ip', nargs='?', help='IP address to parse results for')
    parser.add_argument('--all', '-a', action='store_true',
                       help='Parse all available spider_plus results')
    parser.add_argument('--sort', '-s', choices=['share', 'size', 'name'],
                       default='share', help='Sort output by share (default), size, or name')
    parser.add_argument('--json-output', '-j', action='store_true',
                       help='Output results as JSON')

    args = parser.parse_args()

    # Get spider_plus directory
    spider_plus_dir = Path.home() / '.nxc' / 'modules' / 'nxc_spider_plus'

    if not spider_plus_dir.exists():
        print(f"Error: Spider plus directory not found: {spider_plus_dir}", file=sys.stderr)
        sys.exit(1)

    # Parse results
    if args.all:
        # Parse all JSON files
        json_files = list(spider_plus_dir.glob('*.json'))
        if not json_files:
            print("No spider_plus results found.", file=sys.stderr)
            sys.exit(1)

        all_results = {}
        for json_file in json_files:
            ip = json_file.stem  # filename without .json
            results = parse_spider_plus_file(str(json_file))
            if results:
                all_results[ip] = results

        if args.json_output:
            # Output as JSON
            output = {}
            for ip, results in all_results.items():
                output[ip] = [
                    {'share': share, 'path': path, 'size': size}
                    for share, path, size in results
                ]
            print(json.dumps(output, indent=2))
        else:
            # Print results for each IP
            for ip in sorted(all_results.keys()):
                print_results(all_results[ip], ip, args.sort)

    elif args.ip:
        # Parse specific IP
        json_file = spider_plus_dir / f"{args.ip}.json"

        if not json_file.exists():
            print(f"Error: No results found for IP {args.ip}", file=sys.stderr)
            print(f"Expected file: {json_file}", file=sys.stderr)
            sys.exit(1)

        results = parse_spider_plus_file(str(json_file))

        if args.json_output:
            output = [
                {'share': share, 'path': path, 'size': size}
                for share, path, size in results
            ]
            print(json.dumps(output, indent=2))
        else:
            print_results(results, args.ip, args.sort)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
