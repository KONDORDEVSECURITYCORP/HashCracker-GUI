"""
Results history — persistent cracked-hashes log with export.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

_RESULTS_FILE = Path(__file__).resolve().parent.parent / "results.json"


@dataclass(slots=True)
class CrackResult:
    """One cracked hash record."""

    hash_value: str
    password: str
    algorithm: str = ""
    hash_mode: int = -1
    attack_method: str = ""
    stage_name: str = ""
    cracked_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))


class ResultsStore:
    """Append-only JSON store for cracked results."""

    def __init__(self) -> None:
        self._results: list[CrackResult] = []
        self._load()

    # ── persistence ──────────────────────────────────────────

    def _load(self) -> None:
        if _RESULTS_FILE.exists():
            try:
                data = json.loads(_RESULTS_FILE.read_text(encoding="utf-8"))
                self._results = [
                    CrackResult(**{k: v for k, v in r.items() if k in CrackResult.__slots__})
                    for r in data
                ]
            except (json.JSONDecodeError, TypeError):
                self._results = []

    def _save(self) -> None:
        _RESULTS_FILE.write_text(
            json.dumps([asdict(r) for r in self._results], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    # ── public API ───────────────────────────────────────────

    def add(self, result: CrackResult) -> None:
        self._results.append(result)
        self._save()

    def add_from_line(
        self,
        line: str,
        algorithm: str = "",
        hash_mode: int = -1,
        attack_method: str = "",
        stage_name: str = "",
    ) -> CrackResult | None:
        """Parse a 'hash:password' line and store it."""
        if ":" not in line:
            return None
        parts = line.split(":", 1)
        if len(parts) != 2 or not parts[1]:
            return None
        r = CrackResult(
            hash_value=parts[0].strip(),
            password=parts[1].strip(),
            algorithm=algorithm,
            hash_mode=hash_mode,
            attack_method=attack_method,
            stage_name=stage_name,
        )
        self.add(r)
        return r

    def all(self) -> list[CrackResult]:
        return list(self._results)

    def count(self) -> int:
        return len(self._results)

    def clear(self) -> None:
        self._results.clear()
        self._save()

    # ── export ───────────────────────────────────────────────

    def export_txt(self, path: str) -> int:
        """Export as hash:password lines. Returns count."""
        with open(path, "w", encoding="utf-8") as f:
            for r in self._results:
                f.write(f"{r.hash_value}:{r.password}\n")
        return len(self._results)

    def export_csv(self, path: str) -> int:
        """Export as CSV with all fields. Returns count."""
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["hash", "password", "algorithm", "mode", "attack", "stage", "date"])
            for r in self._results:
                writer.writerow([
                    r.hash_value, r.password, r.algorithm,
                    r.hash_mode, r.attack_method, r.stage_name, r.cracked_at,
                ])
        return len(self._results)

    def export_json(self, path: str) -> int:
        """Export as pretty JSON. Returns count."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in self._results], f, indent=2, ensure_ascii=False)
        return len(self._results)
