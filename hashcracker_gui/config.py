"""
Persistent configuration — JSON store next to the executable.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

_CONFIG_FILE = Path(__file__).resolve().parent.parent / "config.json"


@dataclass(slots=True)
class AppConfig:
    hashcat_path: str = ""
    last_wordlist: str = ""
    last_mask: str = "?a?a?a?a?a?a?a?a"
    last_mode: int = -1
    window_width: int = 1100
    window_height: int = 750

    @classmethod
    def load(cls) -> "AppConfig":
        if _CONFIG_FILE.exists():
            try:
                data = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
                return cls(**{k: v for k, v in data.items() if k in cls.__slots__})
            except (json.JSONDecodeError, TypeError):
                pass
        return cls()

    def save(self) -> None:
        _CONFIG_FILE.write_text(
            json.dumps(asdict(self), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
