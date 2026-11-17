"""Dashboard preferences (theme, language) in ~/.netsentinel/ui.json."""
from __future__ import annotations

import json
from pathlib import Path


def path() -> Path:
    return Path.home() / ".netsentinel" / "ui.json"


def load() -> dict:
    try:
        data = json.loads(path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save(prefs: dict) -> None:
    try:
        p = path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(prefs, indent=2), encoding="utf-8")
    except OSError:
        pass
