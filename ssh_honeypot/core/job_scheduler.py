import threading
import time
import logging
import traceback
from dataclasses import dataclass
from typing import Callable, Any

log = logging.getLogger(__name__)


@dataclass
class ScheduledJob:
    name: str
    callback: Callable[[], Any]
    interval_seconds: int
    last_run: float = 0.0


class JobScheduler:
    def __init__(self):
        self.jobs = []
        self.running = False
        self._thread = None
        self._stop_event = threading.Event()

    def register_job(self, name: str, callback: Callable, interval_seconds: int):
        """Registers a new periodic job."""
        job = ScheduledJob(
            name=name, callback=callback, interval_seconds=interval_seconds
        )
        self.jobs.append(job)
        log.info(f"[Scheduler] Registered job '{name}' (Every {interval_seconds}s)")

    def start(self):
        """Starts the main scheduler loop in a background thread."""
        if self.running:
            return

        self.running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        log.info("[Scheduler] Async Job Scheduler started.")

    def stop(self):
        """Stops the scheduler loop."""
        self.running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        log.info("[Scheduler] Stopped.")

    def _run_loop(self):
        while not self._stop_event.is_set():
            now = time.time()

            for job in self.jobs:
                if now - job.last_run >= job.interval_seconds:
                    try:
                        log.debug(f"[Scheduler] Running job: {job.name}")
                        job.callback()
                        job.last_run = time.time()
                    except Exception as e:
                        log.error(f"[Scheduler] Job '{job.name}' failed: {e}")
                        # log full traceback for debugging
                        # log.error(traceback.format_exc())

            # Sleep a bit to prevent busy loop, but check stop event frequently
            if self._stop_event.wait(timeout=1.0):
                break
