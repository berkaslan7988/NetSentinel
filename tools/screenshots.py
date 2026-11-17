"""Regenerate the README screenshots from the built-in demo traffic.

    python tools/screenshots.py                     # every view, light + dark
    python tools/screenshots.py dark overview flows  # a subset
    python tools/screenshots.py --lang tr            # Turkish interface

Runs the dashboard off-screen in a throwaway home folder (your saved theme and
language are never touched), warm-starts the demo with ten minutes of traffic,
selects a representative alert and flow, and writes 1440x900 PNGs to
assets/screens/<view>-<theme>.png. Needs no models, Npcap or admin rights.
"""
import os
import sys
import tempfile

repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
pkg = os.path.join(repo, "netsentinel")
out = os.path.join(repo, "assets", "screens")
args = sys.argv[1:]
lang = "en"
if "--lang" in args:
    i = args.index("--lang")
    lang = args[i + 1]
    del args[i:i + 2]
themes = args.pop(0) if args and args[0] in ("light", "dark", "both") else "both"
views = args or ["overview", "alerts", "flows", "sources", "models"]

home = tempfile.mkdtemp(prefix="netsentinel-shot-")
os.environ["USERPROFILE"] = home
os.environ["HOME"] = home
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, pkg)
os.chdir(pkg)
os.makedirs(out, exist_ok=True)

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from ui import theme  # noqa: E402
from ui.brand import app_icon  # noqa: E402

app = QApplication(sys.argv[:1])
theme.load_fonts()
app.setFont(theme.ui(13))
app.setWindowIcon(app_icon())

from ui.main_window import MainWindow  # noqa: E402


def pump(ms: int) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


win = MainWindow(autostart_demo=True, theme_name="dark", lang=lang)
win.resize(1440, 900)
win.show()
pump(1500)
win.pipeline._stop.set()          # freeze the traffic so both themes show the same data
pump(400)

s = win.session
brute = [a for a in s.alerts if a.src_ip == "203.0.113.45"]
attack_flow = next((sf for sf in reversed(s.flows)
                    if sf.res.src_ip == "203.0.113.45" and sf.res.iso_anomaly and sf.res.ae_anomaly), None)

suffix = "" if lang == "en" else f"-{lang}"
for name in (["light", "dark"] if themes == "both" else [themes]):
    win.set_theme(name)
    for v in views:
        if v == "overview":
            win.overview.filter.set_current("threats")
        if v == "alerts" and brute:
            win.alerts.focus_alert(brute[-1].alert_id)
        if v == "flows" and attack_flow is not None:
            win.flows.focus_flow(attack_flow)
        win.show_view(v)
        pump(350)
        path = os.path.join(out, f"{v}-{name}{suffix}.png")
        win.grab().save(path)
        print("saved", os.path.relpath(path, repo))
win.close()
