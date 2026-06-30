"""NetSentinel — DetectionWorker (Faz 4).

Thread-safe inference işçisi. Kapanan akışları bir giriş queue'sundan alır,
DetectionEngine ile tahmin eder, DetectionResult'u çıkış queue'suna koyar.

Mimari (roadmap Bölüm 2): yakalama thread'i hafif kalır (sadece akışı queue'ya
atar); ağır iş (feature + inference) bu ayrı worker thread'inde yapılır. UI
thread'i çıkış queue'sundan besleneceği için widget'lara doğrudan dokunulmaz.
"""
from __future__ import annotations

import queue
import threading
from typing import Optional

from detection.engine import DetectionEngine
from flows.flow import Flow

# Worker'ı durdurmak için kullanılan özel işaret (sentinel).
_STOP = object()


class DetectionWorker:
    def __init__(
        self,
        engine: DetectionEngine,
        in_queue: "queue.Queue",
        out_queue: "queue.Queue",
        name: str = "DetectionWorker",
    ) -> None:
        self.engine = engine
        self.in_queue = in_queue
        self.out_queue = out_queue
        self._thread: Optional[threading.Thread] = None
        self._name = name
        self.processed = 0
        self.errors = 0

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name=self._name, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while True:
            item = self.in_queue.get()
            try:
                if item is _STOP:
                    break
                if isinstance(item, Flow):
                    result = self.engine.predict_flow(item)
                    self.out_queue.put(result)
                    self.processed += 1
            except Exception as exc:  # tek bir akış patlarsa worker ölmesin
                self.errors += 1
                print(f"[{self._name}] tahmin hatası: {exc}")
            finally:
                self.in_queue.task_done()

    def stop(self, timeout: float = 2.0) -> None:
        """Worker'ı nazikçe durdurur (sentinel gönderir)."""
        if self._thread is None:
            return
        self.in_queue.put(_STOP)
        self._thread.join(timeout=timeout)
        self._thread = None

    def submit(self, flow: Flow) -> None:
        """Bir akışı işlenmek üzere giriş queue'suna koyar (yakalama tarafından)."""
        self.in_queue.put(flow)
