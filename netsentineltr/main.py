"""NetSentinel — Giriş noktası (Faz 4).

Canlı paketleri yakalar, FlowManager ile akışlara birleştirir; --detect ile
kapanan her akışı eğitilmiş modellerle tahmin edip tehditleri terminale basar.

Pipeline:  Sniffer ─(PacketSummary)─▶ FlowManager ─(Flow)─▶ DetectionWorker ─(Result)─▶ stdout

Kullanım (Windows'ta YÖNETİCİ terminalde):
    python main.py                       # akış yakalama (Faz 1)
    python main.py --packets             # ham paket özetleri (Faz 0)
    python main.py --detect              # canlı tespit (Faz 4, hybrid mod)
    python main.py --detect --mode supervised --duration 30

⚠️ Yalnızca kendi ağında / yetkili lab ortamında çalıştır.
"""
from __future__ import annotations

import argparse
import queue
import sys
import threading
import time

import config
from capture.sniffer import SCAPY_AVAILABLE, Sniffer
from flows.flow import Flow
from flows.manager import FlowManager


def run(duration, iface, bpf_filter, packets_mode, detect, mode, verbose, save) -> int:
    if not SCAPY_AVAILABLE:
        print("[HATA] Scapy bulunamadı. `pip install -r requirements.txt` çalıştır.")
        print("       Windows'ta ayrıca Npcap kurulu olmalı (WinPcap uyumlu modda).")
        return 1

    title = "Faz 4: Canlı Tespit" if detect else (
        "Faz 0: Ham Paket" if packets_mode else "Faz 1: Akış Yakalama")
    print("=" * 64)
    print(f" NetSentinel — {title}")
    print("=" * 64)
    print(f" Arayüz   : {iface or 'varsayılan'}")
    print(f" Filtre   : {bpf_filter or '(yok)'}")
    print(f" Süre     : {duration} sn")
    if detect:
        print(f" Tespit   : {mode} modu")
    print(" ⚠️  Yalnızca kendi/yetkili ağında çalıştır.")
    print("-" * 64)

    pkt_count = 0
    lock = threading.Lock()
    manager = None
    worker = None
    alert_engine = None
    db_writer = None
    printer_stop = threading.Event()

    if packets_mode:
        def on_packet(summary) -> None:
            nonlocal pkt_count
            with lock:
                pkt_count += 1
            print(summary)

        sniffer = Sniffer(on_packet=on_packet, iface=iface, bpf_filter=bpf_filter)

    else:
        if detect:
            # DetectionEngine + AlertEngine + worker zincirini kur
            try:
                from alerts.engine import AlertEngine
                from detection.engine import DetectionEngine
                from detection.worker import DetectionWorker
                engine = DetectionEngine(mode=mode)
            except Exception as exc:
                print(f"[HATA] DetectionEngine yüklenemedi: {exc}")
                print("       Önce Faz 3 eğitimini çalıştırıp models/ doldur.")
                return 1

            # Opsiyonel: kalıcı depolama
            if save:
                from storage.database import Database
                from storage.writer import DBWriter
                db = Database(config.DB_PATH)
                db_writer = DBWriter(db)
                db_writer.start()
                print(f" Kayıt    : {config.DB_PATH}")

            def on_alert(alert) -> None:
                print(f"🚨 ALARM {alert.summary()}")
                if db_writer is not None:
                    db_writer.submit_alert(alert)

            alert_engine = AlertEngine(on_alert=on_alert)

            in_q: "queue.Queue" = queue.Queue()
            out_q: "queue.Queue" = queue.Queue()
            worker = DetectionWorker(engine, in_q, out_q)
            worker.start()

            # Sonuçları AlertEngine'e (+ opsiyonel DB'ye) veren tüketici thread
            def printer() -> None:
                while not printer_stop.is_set() or not out_q.empty():
                    try:
                        res = out_q.get(timeout=0.25)
                    except queue.Empty:
                        continue
                    alert_engine.process(res)            # alarm üretimi/dedup
                    if db_writer is not None:
                        db_writer.submit_result(res)     # akış satırını kaydet
                    if verbose:
                        tag = "•" if res.is_threat else " "
                        print(f"{tag} {res.summary()}")
                    out_q.task_done()

            printer_thread = threading.Thread(target=printer, name="Printer", daemon=True)
            printer_thread.start()

            def on_flow_closed(flow: Flow) -> None:
                worker.submit(flow)  # ağır iş worker'da
        else:
            def on_flow_closed(flow: Flow) -> None:
                print(f"Flow closed: {flow.summary()}")

        manager = FlowManager(
            on_flow_closed=on_flow_closed,
            active_timeout=config.FLOW_ACTIVE_TIMEOUT,
            idle_timeout=config.FLOW_IDLE_TIMEOUT,
        )

        def on_packet(summary) -> None:
            nonlocal pkt_count
            with lock:
                pkt_count += 1
            manager.process_packet(summary)  # yakalama thread'i hafif

        sniffer = Sniffer(on_packet=on_packet, iface=iface, bpf_filter=bpf_filter)
        manager.start_cleanup(interval=config.FLOW_CLEANUP_INTERVAL)

    try:
        sniffer.start()
    except PermissionError:
        print("[HATA] Yetki yok. Windows'ta yönetici, Linux'ta sudo ile çalıştır.")
        return 1
    except Exception as exc:
        print(f"[HATA] Yakalama başlatılamadı: {exc}")
        return 1

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        print("\n[!] Kullanıcı durdurdu.")
    finally:
        sniffer.stop()
        if manager is not None:
            manager.stop_cleanup()
            flushed = manager.flush_all()
            if flushed:
                print(f"[i] {flushed} açık akış kapanışta boşaltıldı.")
        if worker is not None:
            time.sleep(0.5)  # son akışların işlenmesine fırsat ver
            worker.stop()
            printer_stop.set()
        if db_writer is not None:
            time.sleep(0.3)
            db_writer.stop()
            print(f"[i] DB: {db_writer.flows_written} akış, "
                  f"{db_writer.alerts_written} alarm kaydedildi.")

    print("-" * 64)
    summary = f" {pkt_count} paket yakalandı"
    if manager is not None:
        summary += f", {manager.flows_closed} akış kapandı"
    if worker is not None:
        summary += f", {worker.processed} tahmin"
    if alert_engine is not None:
        summary += f", {alert_engine.alerts_emitted} alarm"
    print(summary + f" ({duration} sn).")

    if alert_engine is not None:
        top = alert_engine.top_attackers(5)
        if top:
            print("\n En aktif kaynaklar (top 5):")
            for p in top:
                print(f"   {p.src_ip:18} {p.threat_count} tehdit  "
                      f"max risk {p.max_risk:.0f}")
    print("=" * 64)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="NetSentinel capture/flow/detect")
    parser.add_argument("--duration", type=int, default=config.CAPTURE_DEMO_DURATION)
    parser.add_argument("--iface", default=config.CAPTURE_INTERFACE)
    parser.add_argument("--filter", dest="bpf_filter", default=config.CAPTURE_FILTER)
    parser.add_argument("--packets", action="store_true",
                        help="Ham paket özetleri (Faz 0 modu)")
    parser.add_argument("--detect", action="store_true",
                        help="Canlı tespit (Faz 4)")
    parser.add_argument("--mode", default="hybrid",
                        choices=("supervised", "unsupervised", "hybrid"))
    parser.add_argument("--verbose", action="store_true",
                        help="Her akışın tahminini de bas (alarmlara ek)")
    parser.add_argument("--save", action="store_true",
                        help="Akış ve alarmları SQLite'a kaydet (Faz 6)")
    args = parser.parse_args()
    return run(args.duration, args.iface, args.bpf_filter,
               args.packets, args.detect, args.mode, args.verbose, args.save)


if __name__ == "__main__":
    sys.exit(main())
