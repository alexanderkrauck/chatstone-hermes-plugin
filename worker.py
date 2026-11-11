"""Hermes lifecycle observer; network work never executes on the hook path."""
import threading
import time

from .config import load, read_private, root, write_private
from .runtime import sync


class Worker:
    def __init__(self, home):
        self.home = home
        self.lock = threading.Lock()
        self.ticker = None
        self.next_retry = 0
        self.failures = 0

    def start(self):
        if self.ticker is None:
            self.ticker = threading.Thread(target=self._periodic, daemon=True, name='chatstone-clock')
            self.ticker.start()

    def kick(self, *args, **kwargs):
        del args, kwargs
        if not (root(self.home)/'credentials.json').exists():
            return
        self.start()
        if time.monotonic() < self.next_retry or not self.lock.acquire(blocking=False):
            return
        try:
            # Finite non-daemon work preserves final CLI/cron turns at process exit.
            threading.Thread(target=self._work, daemon=False, name='chatstone-sync').start()
        except RuntimeError:
            self.lock.release()

    def _periodic(self):
        while True:
            time.sleep(30)
            self.kick()

    def _work(self):
        from .cli import lease
        try:
            # Let Hermes commit its final persisted row before reading the tail.
            time.sleep(.5)
            with lease(self.home):
                value = sync(load(self.home))
                value['last_error'] = None
                write_private(root(self.home)/'status.json', value)
            self.failures = 0
        except Exception as error:  # noqa: BLE001 -- no private exception text
            code = getattr(error, 'code', '')
            if code not in ('SPOOL_BUSY', 'PLUGIN_BUSY'):
                self.failures += 1
                self.next_retry = time.monotonic()+min(300, 2**min(self.failures, 8))
                path = root(self.home)/'status.json'
                try:
                    previous = read_private(path)
                except FileNotFoundError:
                    previous = {}
                from .errors import guidance
                previous['last_error'] = guidance(code)
                previous['last_error_code'] = code if code in {
                    'INGEST_CAPACITY_EXCEEDED', 'RATE_LIMITED', 'SERVICE_UNAVAILABLE',
                    'UNAUTHORIZED', 'FORBIDDEN', 'INGEST_DISABLED', 'DELIVERY_REFUSED'} else 'SYNC_UNAVAILABLE'
                write_private(path, previous)
        finally:
            self.lock.release()
