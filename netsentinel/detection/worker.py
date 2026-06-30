"""NetSentinel - DetectionWorker (Phase 4).

A thread-safe inference worker. Pulls closed flows from an input queue, predicts
with the DetectionEngine, and puts a DetectionResult on the output queue.

Architecture (roadmap Section 2): the capture thread stays light (it only puts
the flow on a queue); the heavy work (feature + inference) happens on this
separate worker thread. The UI thread is fed from the output queue, so widgets
are never touched directly.
"""
from __future__ import annotations

import queue
import threading
from typing import Optional

from detection.engine import DetectionEngine
from flows.flow import Flow

# Special sentinel used to stop the worker.
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
            except Exception as exc:  # one bad flow shouldn't kill the worker
                self.errors += 1
                print(f"[{self._name}] prediction error: {exc}")
            finally:
                self.in_queue.task_done()

    def stop(self, timeout: float = 2.0) -> None:
        """Stops the worker gracefully (sends the sentinel)."""
        if self._thread is None:
            return
        self.in_queue.put(_STOP)
        self._thread.join(timeout=timeout)
        self._thread = None

    def submit(self, flow: Flow) -> None:
        """Puts a flow on the input queue to be processed (by the capture side)."""
        self.in_queue.put(flow)
