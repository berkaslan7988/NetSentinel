"""Every t("...") string in ui/ has a Turkish translation with the same fields."""
import ast
import string
from pathlib import Path

from ui import i18n

UI_DIR = Path(__file__).resolve().parent.parent / "ui"


def ui_strings():
    found = set()
    for path in UI_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "t"
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                found.add(node.args[0].value)
    return found


def fields(s):
    return sorted(f for _, f, _, _ in string.Formatter().parse(s) if f)


def test_every_ui_string_has_turkish():
    missing = sorted(s for s in ui_strings() if s not in i18n.TR)
    assert not missing, f"untranslated: {missing}"


def test_translations_keep_format_fields():
    bad = [k for k, v in i18n.TR.items() if fields(k) != fields(v)]
    assert not bad, f"format fields differ: {bad}"


def test_turkish_formatting():
    i18n.set_language("tr")
    try:
        assert i18n.num(1204) == "1.204"
        assert i18n.num(842.6, 1) == "842,6"
        assert i18n.upper("risk") == "RİSK"
    finally:
        i18n.set_language("en")
    assert i18n.num(1204) == "1,204"
