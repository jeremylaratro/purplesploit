"""Shared output neutralization and link policy."""

from urllib.parse import urlsplit


def spreadsheet_safe(value):
    """Prevent CSV/XLSX cells from being interpreted as formulas."""
    if not isinstance(value, str):
        return value
    candidate = value.lstrip()
    if candidate.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def restore_spreadsheet_value(value):
    """Undo our marker only for explicitly marked PurpleSploit round trips."""
    if isinstance(value, str) and value.startswith("'"):
        candidate = value[1:].lstrip()
        if candidate.startswith(("=", "+", "-", "@", "\t", "\r")):
            return value[1:]
    return value


def safe_reference(value: str) -> str:
    """Allow only absolute HTTP(S) references in active report links."""
    value = str(value).strip()
    parsed = urlsplit(value)
    return value if parsed.scheme in {"http", "https"} and parsed.netloc else ""
