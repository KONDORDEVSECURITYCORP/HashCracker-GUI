"""
SQL dump / email:hash parser.

Reads files in common database dump formats and extracts
email→hash mappings. Supports:

  - email:hash              (plain dump)
  - email:hash:salt         (salted)
  - user:email:hash         (3-column)
  - id:user:email:hash      (4-column, numeric ID)
  - SQL INSERT statements   (INSERT INTO ... VALUES ...)
  - CSV with headers        (auto-detect email/hash columns)

Generates:
  - A pure-hash file for hashcat (one hash per line)
  - A mapping dict: hash → list[email] for result reconstruction
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from pathlib import Path


_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
_SQL_INSERT_RE = re.compile(
    r"INSERT\s+INTO\s+[`'\"]?\w+[`'\"]?\s*(?:\([^)]*\))?\s*VALUES\s*",
    re.IGNORECASE,
)
_SQL_VALUES_RE = re.compile(r"\(([^)]+)\)")

# Minimum hex length to consider a hash (MD5 = 32)
_MIN_HASH_LEN = 16


@dataclass(slots=True)
class DumpResult:
    """Result of parsing a dump file."""

    hash_to_emails: dict[str, list[str]] = field(default_factory=dict)
    hashes: list[str] = field(default_factory=list)
    total_records: int = 0
    format_detected: str = ""
    errors: list[str] = field(default_factory=list)


def _is_email(s: str) -> bool:
    return bool(_EMAIL_RE.match(s.strip()))


def _is_hash(s: str) -> bool:
    s = s.strip()
    # Hex hash (MD5, SHA1, SHA256, etc.)
    if _HEX_RE.match(s) and len(s) >= _MIN_HASH_LEN:
        return True
    # Bcrypt, scrypt, crypt, etc.
    if s.startswith(("$2", "$1$", "$5$", "$6$", "$apr1$", "$argon2",
                     "$krb5", "$office$", "$rar5$", "$keepass$",
                     "$bitcoin$", "$ethereum$", "{SSHA", "{SHA")):
        return True
    return False


def _add_mapping(result: DumpResult, email: str, hash_val: str) -> None:
    email = email.strip()
    hash_val = hash_val.strip()
    if hash_val not in result.hash_to_emails:
        result.hash_to_emails[hash_val] = []
        result.hashes.append(hash_val)
    result.hash_to_emails[hash_val].append(email)
    result.total_records += 1


def _parse_sql_inserts(content: str, result: DumpResult) -> bool:
    """Try parsing SQL INSERT INTO ... VALUES ... statements."""
    matches = list(_SQL_INSERT_RE.finditer(content))
    if not matches:
        return False

    found = False
    for m in matches:
        rest = content[m.end():]
        for row_match in _SQL_VALUES_RE.finditer(rest):
            values = [v.strip().strip("'\"") for v in row_match.group(1).split(",")]
            emails = [v for v in values if _is_email(v)]
            hashes = [v for v in values if _is_hash(v)]
            if emails and hashes:
                _add_mapping(result, emails[0], hashes[0])
                found = True

    if found:
        result.format_detected = "SQL INSERT"
    return found


def _parse_colon_separated(lines: list[str], result: DumpResult) -> bool:
    """Parse email:hash or variations with colons."""
    found = False

    for line in lines:
        line = line.strip()
        if not line or line.startswith(("--", "#", "//")):
            continue

        parts = line.split(":")
        if len(parts) < 2:
            continue

        # Find email and hash in the parts
        emails = [p for p in parts if _is_email(p)]
        hashes = [p for p in parts if _is_hash(p)]

        if emails and hashes:
            _add_mapping(result, emails[0], hashes[0])
            found = True
        elif len(parts) == 2:
            # Could be email:hash where email doesn't match strict regex
            # or username:hash
            a, b = parts[0].strip(), parts[1].strip()
            if _is_hash(b) and "@" in a:
                _add_mapping(result, a, b)
                found = True
            elif _is_hash(a) and "@" in b:
                _add_mapping(result, b, a)
                found = True

    if found:
        result.format_detected = "email:hash"
    return found


def _parse_csv(content: str, result: DumpResult) -> bool:
    """Try CSV with headers (auto-detect email/hash columns)."""
    try:
        dialect = csv.Sniffer().sniff(content[:4096])
        reader = csv.DictReader(io.StringIO(content), dialect=dialect)
    except csv.Error:
        for sep in [",", ";", "\t", "|"]:
            if sep in content[:500]:
                reader = csv.DictReader(io.StringIO(content), delimiter=sep)
                break
        else:
            return False

    if not reader.fieldnames:
        return False

    # Find columns
    email_col = None
    hash_col = None

    email_keywords = {"email", "mail", "correo", "user_email", "e-mail", "username"}
    hash_keywords = {"hash", "password", "pass", "pwd", "password_hash",
                     "user_pass", "passwd", "hashed_password", "md5", "sha1", "sha256"}

    for col in reader.fieldnames:
        col_lower = col.strip().lower()
        if col_lower in email_keywords:
            email_col = col
        elif col_lower in hash_keywords:
            hash_col = col

    if not email_col or not hash_col:
        return False

    found = False
    for row in reader:
        email = row.get(email_col, "").strip()
        hash_val = row.get(hash_col, "").strip()
        if email and hash_val and (_is_email(email) or "@" in email) and _is_hash(hash_val):
            _add_mapping(result, email, hash_val)
            found = True

    if found:
        result.format_detected = "CSV"
    return found


def parse_dump_file(filepath: str) -> DumpResult:
    """
    Auto-detect format and parse a dump file.

    Returns DumpResult with hash→email mapping.
    """
    result = DumpResult()
    path = Path(filepath)

    if not path.is_file():
        result.errors.append(f"Archivo no encontrado: {filepath}")
        return result

    content = path.read_text(encoding="utf-8", errors="replace")
    lines = content.strip().splitlines()

    # Try SQL INSERT first
    if _parse_sql_inserts(content, result):
        return result

    # Try CSV with headers
    if _parse_csv(content, result):
        return result

    # Try colon-separated (most common dump format)
    if _parse_colon_separated(lines, result):
        return result

    result.errors.append("No se pudo detectar el formato del archivo.")
    return result


def write_hashcat_file(hashes: list[str], output_path: str) -> str:
    """Write a pure-hash file for hashcat. Returns the path."""
    with open(output_path, "w", encoding="utf-8") as f:
        for h in hashes:
            f.write(h + "\n")
    return output_path


def map_results(
    cracked_lines: list[str],
    hash_to_emails: dict[str, list[str]],
) -> list[tuple[str, str, str]]:
    """
    Map cracked hash:password lines back to emails.

    Returns list of (email, hash, password) tuples.
    """
    mapped: list[tuple[str, str, str]] = []

    for line in cracked_lines:
        line = line.strip()
        if ":" not in line:
            continue
        hash_val, password = line.split(":", 1)
        hash_val = hash_val.strip()
        password = password.strip()

        emails = hash_to_emails.get(hash_val, [])
        if emails:
            for email in emails:
                mapped.append((email, hash_val, password))
        else:
            mapped.append(("", hash_val, password))

    return mapped
