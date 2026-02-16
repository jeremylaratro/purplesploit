#!/bin/bash

# delete_small_files.sh - Delete files smaller than specified size
# Usage: ./delete_small_files.sh --size <size> [--path <directory>] [--dry-run]

set -euo pipefail

# Defaults
SIZE=""
TARGET_PATH="."
DRY_RUN=false

usage() {
    cat <<EOF
Usage: $(basename "$0") --size <size> [OPTIONS]

Delete all files smaller than the specified size.

Required:
  --size <size>     Minimum file size (e.g., 100, 1K, 1M, 1G)
                    Files SMALLER than this will be deleted

Options:
  --path <dir>      Target directory (default: current directory)
  --dry-run         Show what would be deleted without actually deleting
  -h, --help        Show this help message

Examples:
  $(basename "$0") --size 1K                    # Delete files < 1KB in current dir
  $(basename "$0") --size 100 --path /tmp       # Delete files < 100 bytes in /tmp
  $(basename "$0") --size 1M --dry-run          # Preview files < 1MB to delete
EOF
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --size)
            SIZE="$2"
            shift 2
            ;;
        --path)
            TARGET_PATH="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Error: Unknown option: $1"
            usage
            ;;
    esac
done

# Validate required args
if [[ -z "$SIZE" ]]; then
    echo "Error: --size is required"
    usage
fi

# Normalize size for find:
# - find uses 'c' for bytes (no suffix), 'k' for KB, 'M' for MB, 'G' for GB
# - Convert K to k, add 'c' suffix if just a number (bytes)
if [[ "$SIZE" =~ ^[0-9]+$ ]]; then
    SIZE="${SIZE}c"  # Plain number = bytes, find needs 'c' suffix
else
    SIZE=$(echo "$SIZE" | sed 's/K$/k/; s/B$//i')
fi

if [[ ! -d "$TARGET_PATH" ]]; then
    echo "Error: Directory '$TARGET_PATH' does not exist"
    exit 1
fi

# Find and process files
if $DRY_RUN; then
    echo "DRY RUN - Files that would be deleted (smaller than $SIZE):"
    find "$TARGET_PATH" -type f -size -"$SIZE" -print
    echo ""
    echo "File count: $(find "$TARGET_PATH" -type f -size -"$SIZE" | wc -l)"
else
    count=$(find "$TARGET_PATH" -type f -size -"$SIZE" | wc -l)
    if [[ $count -eq 0 ]]; then
        echo "No files smaller than $SIZE found in $TARGET_PATH"
        exit 0
    fi

    echo "Deleting $count files smaller than $SIZE in $TARGET_PATH..."
    find "$TARGET_PATH" -type f -size -"$SIZE" -print -delete
    echo "Done. Deleted $count files."
fi
