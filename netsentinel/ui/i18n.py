"""NetSentinel - interface language (English / Turkish), Qt-independent.

Strings are looked up by their English text, so the English UI needs no table
and a missing Turkish entry falls back to English instead of breaking.
``tests/test_i18n.py`` checks that every ``t("...")`` literal in ui/ has a
Turkish translation.

    t("Open alerts")                 -> "Açık uyarılar" when the language is "tr"
    t("{n} flows", n=412)            -> "412 akış"
"""
from __future__ import annotations

import locale
import os

LANGUAGES = ("en", "tr")
_lang = "en"


def default_language() -> str:
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        val = os.environ.get(var, "")
        if val:
            return "tr" if val.lower().startswith("tr") else "en"
    try:
        loc = locale.getlocale()[0] or ""
    except ValueError:
        loc = ""
    return "tr" if loc.lower().startswith(("tr", "turkish")) else "en"


def set_language(lang: str) -> None:
    global _lang
    _lang = lang if lang in LANGUAGES else "en"


def language() -> str:
    return _lang


def t(text: str, **kw) -> str:
    out = TR.get(text, text) if _lang == "tr" else text
    return out.format(**kw) if kw else out


def upper(text: str) -> str:
    """Uppercase that keeps Turkish dotted i (risk -> RİSK)."""
    if _lang == "tr":
        text = text.replace("i", "İ")
    return text.upper()


def num(n: float, digits: int = 0) -> str:
    """Thousands-grouped number in the current language (1,204 / 1.204)."""
    s = f"{n:,.{digits}f}"
    if _lang == "tr":
        s = s.replace(",", "\x00").replace(".", ",").replace("\x00", ".")
    return s


def pct(value: float, digits: int = 1) -> str:
    """A percentage in the current language: 12.5% / %12,5."""
    n = num(value, digits)
    return f"%{n}" if _lang == "tr" else f"{n}%"


def duration(seconds: float) -> str:
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return t("{s}s", s=seconds)
    m, s = divmod(seconds, 60)
    if m < 60:
        return t("{m}m {s:02d}s", m=m, s=s)
    h, m = divmod(m, 60)
    return t("{h}h {m:02d}m", h=h, m=m)


def ago(seconds: float) -> str:
    if seconds < 2:
        return t("now")
    return t("{d} ago", d=duration(seconds))


TR: dict[str, str] = {
    # navigation and chrome
    "Overview": "Genel bakış", "Alerts": "Alarmlar", "Flows": "Akışlar", "Sources": "Kaynaklar",
    "Models": "Modeller", "Source": "Kaynak", "Demo": "Demo", "Live capture": "Canlı yakalama",
    "Replay CSV": "CSV oynat", "Replay database": "Veritabanını oynat",
    "Hybrid": "Hibrit", "Supervised": "Denetimli", "Unsupervised": "Denetimsiz",
    "Start": "Başlat", "Stop": "Durdur", "Switch theme": "Temayı değiştir",
    "Language: English / Türkçe": "Dil: English / Türkçe",
    "Pipeline": "Akış hattı", "Features": "Öznitelik", "Detect": "Tespit",
    "synthetic": "sentetik", "simulated": "simüle", "idle": "boşta", "{n} pkt/s": "{n} paket/s",
    "{n} open": "{n} açık",
    "Demo mode: synthetic traffic scored by the real risk and alert engine. No models, capture driver or admin rights needed.":
        "Demo modu: sentetik trafik, gerçek risk ve alarm motoruyla puanlanır. Model, yakalama sürücüsü ya da yönetici hakkı gerekmez.",
    "Live capture: run as administrator, on your own network only.":
        "Canlı yakalama: yönetici olarak ve yalnızca kendi ağında çalıştır.",
    "Live capture needs trained models in models/. Train them, or use Demo.":
        "Canlı yakalama için models/ içinde eğitilmiş modeller gerekir. Modelleri eğit ya da Demo modunu kullan.",
    "Replay CSV: {name}": "CSV oynatma: {name}", "no file picked": "dosya seçilmedi",
    "Replay database: {path}": "Veritabanı oynatma: {path}",
    "Pick a CIC-IDS2017 CSV": "Bir CIC-IDS2017 CSV dosyası seç",
    "No recorded session yet. Run main.py --detect --save first ({path}).":
        "Henüz kayıtlı oturum yok. Önce main.py --detect --save çalıştır ({path}).",
    "No trained models in models/. Train them (see README), or switch the source to Demo.":
        "models/ içinde eğitilmiş model yok. Modelleri eğit (README'ye bak) ya da kaynağı Demo yap.",
    "Could not start: {err}": "Başlatılamadı: {err}",

    # severities
    "CRIT": "KRİTİK", "HIGH": "YÜKSEK", "MED": "ORTA", "LOW": "DÜŞÜK",
    "Critical": "Kritik", "High": "Yüksek", "Medium": "Orta", "Benign": "Zararsız",
    "critical": "kritik", "high": "yüksek", "medium": "orta", "no alert": "alarm yok",

    # overview
    "Flows scored": "Puanlanan akış", "Threat flows": "Tehdit akışı", "Open alerts": "Açık alarm",
    "Throughput": "Veri hızı", "Peak risk": "En yüksek risk",
    "{rate} flows / s right now": "şu an saniyede {rate} akış",
    "{pct} of all flows, risk 25+": "tüm akışlar içinde {pct}, risk 25+",
    "ATTACK": "SALDIRI", "BENIGN": "ZARARSIZ",
    "{total} this session": "bu oturumda {total}", "{ip} at {time}": "{ip}, {time}",
    "no risky flow yet": "henüz riskli akış yok",
    "Flow timeline": "Akış zaman çizelgesi",
    "last 10 min, 5 s buckets, threat flows stacked on top": "son 10 dk, 5 sn'lik dilimler, tehdit akışları üstte",
    "No flows yet": "Henüz akış yok",
    "Press Start. Demo mode needs no models or capture driver.":
        "Başlat'a bas. Demo modu model ya da yakalama sürücüsü istemez.",
    "Live flows": "Canlı akışlar", "newest first": "en yenisi üstte", "All": "Tümü", "Threats": "Tehditler",
    "Filter by IP or port": "IP ya da porta göre süz",
    "Pick a source in the top bar and press Start.": "Üst çubuktan bir kaynak seç ve Başlat'a bas.",
    "grouped per source, {s} s window": "kaynağa göre gruplu, {s} sn pencere",
    "{n} open, grouped per source over {s} s": "{n} açık, kaynağa göre {s} sn içinde gruplu",
    "No alerts": "Alarm yok", "Flows with risk 25 or more open an alert.": "Riski 25 ve üstü olan akışlar alarm açar.",
    "Top sources": "Öne çıkan kaynaklar", "by threat flows": "tehdit akışına göre",
    "No threat sources yet": "Henüz tehdit kaynağı yok",
    "{kind} · {n} flows · {span} · to ": "{kind} · {n} akış · {span} · hedef ",
    "{n} flows": "{n} akış", "{n} benign": "{n} zararsız",

    # flows
    "Time": "Zaman", "Destination": "Hedef", "Proto": "Prot.", "Bytes": "Bayt", "Duration": "Süre",
    "Verdict": "Karar", "Signals": "Sinyaller", "Risk": "Risk",
    "Flow detail": "Akış ayrıntısı",
    "Select a flow to see each model's output and how its risk score was built.":
        "Her modelin çıktısını ve risk puanının nasıl oluştuğunu görmek için bir akış seç.",
    "Protocol": "Protokol", "Seen": "Görülme", "Packets": "Paket",
    "{f} out / {b} back": "{f} giden / {b} dönen",
    "Model signals": "Model sinyalleri", "Risk score": "Risk puanı",
    "RF: attack": "RF: saldırı", "RF: benign": "RF: zararsız", "RF not loaded": "RF yüklü değil",
    "{shown} shown of {total} scored this session": "bu oturumda puanlanan {total} akıştan {shown} tanesi",
    "not loaded": "yüklü değil", "flagged": "işaretledi", "normal": "normal",
    "IF + AE, {state}": "IF + AE, {state}", "both agree": "ikisi de", "one model": "tek model",
    "neither": "hiçbiri", "RandomForest": "RandomForest",
    "Medium from {m}, high from {h}, critical from {c}": "{m}+ orta, {h}+ yüksek, {c}+ kritik",
    "Volume: {n} flows in the window": "Hacim: pencerede {n} akış", "no floor": "taban yok",

    # alerts
    "Severity": "Önem", "Seen as": "Tür", "First seen": "İlk görülme", "Last seen": "Son görülme",
    "Status": "Durum", "Open": "Açık", "Closed": "Kapalı", "Alert detail": "Alarm ayrıntısı",
    "An alert opens when a flow scores 25 or more. Flows from the same source within {s} s are grouped into it.":
        "Bir akışın puanı 25 ve üstü olunca alarm açılır. Aynı kaynaktan {s} sn içinde gelen akışlar bu alarma eklenir.",
    "Select an alert to see its timeline and score breakdown.":
        "Zaman çizelgesini ve puan dökümünü görmek için bir alarm seç.",
    "Target": "Hedef", "Alert ID": "Alarm no",
    "Activity from this source, last 10 min": "Bu kaynağın etkinliği, son 10 dk",
    "Why this score (peak flow)": "Bu puan neden (en riskli akış)",
    "Latest flows from this source": "Bu kaynağın son akışları",
    "Open, last flow {ago}": "Açık, son akış {ago}",
    "Known attack": "Bilinen saldırı", "Anomaly": "Anomali", "Known attack + anomaly": "Bilinen saldırı + anomali",
    "{open} open, {total} this session, grouped per source over {s} s":
        "{open} açık, bu oturumda {total}, kaynağa göre {s} sn içinde gruplu",

    # sources
    "Network": "Ağ", "Total risk": "Toplam risk", "Activity, 10 min": "Etkinlik, 10 dk",
    "Last threat": "Son tehdit", "internal": "iç ağ", "external": "dış ağ",
    "Most targeted hosts": "En çok hedef alınan cihazlar", "by threat flows received": "gelen tehdit akışına göre",
    "Host": "Cihaz", "Ports": "Portlar", "No targets yet": "Henüz hedef yok",
    "A source appears here once one of its flows scores {n} or more.":
        "Bir kaynağın akışlarından biri {n} ve üstü puan alınca burada görünür.",
    "{n} sources raised threat flows: {e} external, {i} internal. Click one to open its alert.":
        "{n} kaynak tehdit akışı üretti: {e} dış ağ, {i} iç ağ. Alarmını açmak için birine tıkla.",

    # models
    "Supervised, known attacks": "Denetimli, bilinen saldırılar",
    "Unsupervised, outliers": "Denetimsiz, aykırı değerler",
    "Unsupervised, reconstruction": "Denetimsiz, yeniden oluşturma",
    "Learns the labelled attacks in CIC-IDS2017. Its attack probability carries {w} of the risk score.":
        "CIC-IDS2017'deki etiketli saldırıları öğrenir. Saldırı olasılığı risk puanında {w} ağırlık taşır.",
    "Trained on benign traffic only. Flags flows that are easy to isolate, which catches traffic unlike anything seen in training.":
        "Yalnızca zararsız trafikle eğitildi. Kolay yalıtılan akışları işaretler; böylece eğitimde hiç görülmemiş trafiği yakalar.",
    "A PyTorch network that rebuilds benign flows. A reconstruction error above the {p}th percentile of benign traffic is anomalous.":
        "Zararsız akışları yeniden oluşturan bir PyTorch ağı. Zararsız trafiğin {p}. yüzdeliğini aşan yeniden oluşturma hatası anomalidir.",
    "Weight in risk": "Riskteki ağırlık", "File": "Dosya", "Trained on": "Eğitim verisi",
    "benign flows": "zararsız akışlar", "Architecture": "Mimari", "Error threshold": "Hata eşiği",
    "F1 on CIC-IDS2017": "CIC-IDS2017 F1", "Precision": "Kesinlik", "Recall": "Duyarlılık",
    "False positives": "Yanlış pozitif",
    "Simulated in demo": "Demoda simüle", "Loaded": "Yüklü", "On disk": "Diskte", "Not trained": "Eğitilmedi",
    "How risk is scored": "Risk nasıl puanlanır", "Worked examples": "Örnekler",
    "RF {p}, {flags} flag": "RF {p}, {flags} işaretli",
    "risk = {a} × RF attack probability + {b} × IF/AE agreement":
        "risk = {a} × RF saldırı olasılığı + {b} × IF/AE uyumu",
    "Agreement is {both} when both unsupervised models flag the flow, {one} when one does, 0 when neither does. A lone autoencoder flag cannot raise an alert.":
        "İki denetimsiz model de akışı işaretlerse uyum {both}, biri işaretlerse {one}, hiçbiri işaretlemezse 0 olur. Tek başına autoencoder işareti alarm açamaz.",
    "An alert opens at risk {m}. Threat flows from one source within {w} s are merged into one alert, and its volume raises the floor: 10 flows medium, 30 high, 100 critical.":
        "Alarm {m} riskte açılır. Bir kaynaktan {w} sn içinde gelen tehdit akışları tek alarmda birleşir ve hacim tabanı yükseltir: 10 akış orta, 30 yüksek, 100 kritik.",
    "Features per flow": "Akış başına öznitelik", "CICFlowMeter order": "CICFlowMeter sırasıyla",
    "Inference, benchmark": "Çıkarım, ölçüm", "p95 about 10 ms": "p95 yaklaşık 10 ms",
    "Sustained rate": "Sürekli hız", "{n} flows/s": "{n} akış/s",
    "Training data": "Eğitim verisi", "CIC-IDS2017 flows": "CIC-IDS2017 akışı",
    "This session: {ms} ms per flow, measured live.": "Bu oturum: akış başına {ms} ms, canlı ölçüldü.",
    "Demo mode draws model outputs from these measured rates instead of running the models, so it needs no trained files.":
        "Demo modu modelleri çalıştırmak yerine çıktıları bu ölçülmüş oranlardan üretir; eğitilmiş dosya gerekmez.",
    "Train the models with the scripts in training/ to run live detection.":
        "Canlı tespit için modelleri training/ içindeki betiklerle eğit.",

    # time
    "now": "şimdi", "{d} ago": "{d} önce", "{s}s": "{s} sn", "{m}m {s:02d}s": "{m} dk {s:02d} sn",
    "{h}h {m:02d}m": "{h} sa {m:02d} dk",
}
