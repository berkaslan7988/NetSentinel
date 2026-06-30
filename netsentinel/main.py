"""NetSentinel - Entry point (Phase 4).

Captures live packets, aggregates them into flows with the FlowManager; with
--detect it predicts on each closed flow using the trained models and prints
threats to the terminal.

Pipeline:  Sniffer -(PacketSummary)-> FlowManager -(Flow)-> DetectionWorker -(Result)-> stdout

Usage (run as ADMINISTRATOR on Windows):
    python main.py                       # flow capture (Phase 1)
    python main.py --packets             # raw packet summaries (Phase 0)
    python main.py --detect              # live detection (Phase 4)
    python main.py --detect --save       # ...and persist flows/alerts to SQLite
    python main.py --detect --mode supervised --verbose

WARNING: run only on your own / authorized network.
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
        print("[ERROR] Scapy not found. Run `pip install -r requirements.txt`.")
        print("        On Windows, Npcap must also be installed (WinPcap-compatible mode).")
        return 1

    title = "Phase 4: Live Detection" if detect else (
        "Phase 0: Raw Packets" if packets_mode else "Phase 1: Flow Capture")
    print("=" * 64)
    print(f" NetSentinel - {title}")
    print("=" * 64)
    print(f" Interface : {iface or 'default'}")
    print(f" Filter    : {bpf_filter or '(none)'}")
    print(f" Duration  : {duration} s")
    if detect:
        print(f" Detection : {mode} mode")
    print(" WARNING: run only on your own / authorized network.")
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
            # Build the DetectionEngine + AlertEngine + worker chain
            try:
                from alerts.engine import AlertEngine
                from detection.engine import DetectionEngine
                from detection.worker import DetectionWorker
                engine = DetectionEngine(mode=mode)
            except Exception as exc:
                print(f"[ERROR] could not load DetectionEngine: {exc}")
                print("        Run Phase 3 training first to populate models/.")
                return 1

            # Optional: persistent storage
            if save:
                from storage.database import Database
                from storage.writer import DBWriter
                db = Database(config.DB_PATH)
                db_writer = DBWriter(db)
                db_writer.start()
                print(f" Storage   : {config.DB_PATH}")

            def on_alert(alert) -> None:
                print(f"ALERT {alert.summary()}")
                if db_writer is not None:
                    db_writer.submit_alert(alert)

            alert_engine = AlertEngine(on_alert=on_alert)

            in_q: "queue.Queue" = queue.Queue()
            out_q: "queue.Queue" = queue.Queue()
            worker = DetectionWorker(engine, in_q, out_q)
            worker.start()

            # Consumer thread feeding the AlertEngine (+ optional DB) - no spam
            def printer() -> None:
                while not printer_stop.is_set() or not out_q.empty():
                    try:
                        res = out_q.get(timeout=0.25)
                    except queue.Empty:
                        continue
                    alert_engine.process(res)            # alert generation/dedup
                    if db_writer is not None:
                        db_writer.submit_result(res)     # store the flow row
                    if verbose:
                        tag = "*" if res.is_threat else " "
                        print(f"{tag} {res.summary()}")
                    out_q.task_done()

            printer_thread = threading.Thread(target=printer, name="Printer", daemon=True)
            printer_thread.start()

            def on_flow_closed(flow: Flow) -> None:
                worker.submit(flow)  # heavy work on the worker
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
            manager.process_packet(summary)  # keep the capture thread light

        sniffer = Sniffer(on_packet=on_packet, iface=iface, bpf_filter=bpf_filter)
        manager.start_cleanup(interval=config.FLOW_CLEANUP_INTERVAL)

    try:
        sniffer.start()
    except PermissionError:
        print("[ERROR] No permission. Run as Administrator on Windows, sudo on Linux.")
        return 1
    except Exception as exc:
        print(f"[ERROR] could not start capture: {exc}")
        return 1

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
    finally:
        sniffer.stop()
        if manager is not None:
            manager.stop_cleanup()
            flushed = manager.flush_all()
            if flushed:
                print(f"[i] {flushed} open flows flushed on shutdown.")
        if worker is not None:
            time.sleep(0.5)  # give the last flows a chance to be processed
            worker.stop()
            printer_stop.set()
        if db_writer is not None:
            time.sleep(0.3)
            db_writer.stop()
            print(f"[i] DB: {db_writer.flows_written} flows, "
                  f"{db_writer.alerts_written} alerts saved.")

    print("-" * 64)
    summary = f" {pkt_count} packets captured"
    if manager is not None:
        summary += f", {manager.flows_closed} flows closed"
    if worker is not None:
        summary += f", {worker.processed} predictions"
    if alert_engine is not None:
        summary += f", {alert_engine.alerts_emitted} alerts"
    print(summary + f" ({duration} s).")

    if alert_engine is not None:
        top = alert_engine.top_attackers(5)
        if top:
            print("\n Most active sources (top 5):")
            for p in top:
                print(f"   {p.src_ip:18} {p.threat_count} threats  "
                      f"max risk {p.max_risk:.0f}")
    print("=" * 64)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="NetSentinel capture/flow/detect")
    parser.add_argument("--duration", type=int, default=config.CAPTURE_DEMO_DURATION)
    parser.add_argument("--iface", default=config.CAPTURE_INTERFACE)
    parser.add_argument("--filter", dest="bpf_filter", default=config.CAPTURE_FILTER)
    parser.add_argument("--packets", action="store_true",
                        help="Raw packet summaries (Phase 0 mode)")
    parser.add_argument("--detect", action="store_true",
                        help="Live detection (Phase 4)")
    parser.add_argument("--mode", default="hybrid",
                        choices=("supervised", "unsupervised", "hybrid"))
    parser.add_argument("--verbose", action="store_true",
                        help="Also print every flow's prediction (in addition to alerts)")
    parser.add_argument("--save", action="store_true",
                        help="Persist flows and alerts to SQLite (Phase 6)")
    args = parser.parse_args()
    return run(args.duration, args.iface, args.bpf_filter,
               args.packets, args.detect, args.mode, args.verbose, args.save)


if __name__ == "__main__":
    sys.exit(main())
