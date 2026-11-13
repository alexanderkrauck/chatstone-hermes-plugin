"""Hermes lifecycle observer; network work never executes on the hook path."""
import threading
import time

from .config import load, root
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
                from .cli import save_success
                save_success(self.home, value)
            self.failures = 0
        except Exception as error:  # noqa: BLE001 -- no private exception text
            from .errors import BUSY_CODES
            if getattr(error, 'code', None) in BUSY_CODES:
                return  # Another owner is working; retry on the normal next tick.
            self.failures += 1
            self.next_retry = time.monotonic()+min(300, 2**min(self.failures, 8))
            import sys

            from .errors import cause, describe, save_failure
            print('Chatstone: '+describe(cause(error)), file=sys.stderr)
            try:
                save_failure(self.home, error)
            except Exception as saving_error:  # noqa: BLE001 -- content-free fallback
                print('Chatstone status write: '+describe(cause(saving_error)), file=sys.stderr)
        finally:
            self.lock.release()
