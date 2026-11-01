"""Same temporary Windows sleep guard used in continuation046; no permanent setting change."""
import ctypes
import json
import os
from pathlib import Path
import time

def append(path, value):
    with Path(path).open('a', encoding='utf-8') as f:
        f.write(json.dumps(dict(utc_ns=time.time_ns(), **value))+'\n')

class SleepGuard:
    """Temporary per-thread Windows system-awake request, restored on exit.

    Does not prevent manual sleep, lid closure, shutdown, or USB power policies.
    """
    def __init__(self, log_path):
        self.log_path = Path(log_path)
        self.previous = None
        self.setter = None

    def __enter__(self):
        if os.name != "nt":
            append(self.log_path, {"event": "system_awake_not_applicable", "platform": os.name})
            return self
        self.setter = ctypes.windll.kernel32.SetThreadExecutionState
        self.setter.argtypes = [ctypes.c_uint32]
        self.setter.restype = ctypes.c_uint32
        previous = self.setter(0x80000001)  # ES_CONTINUOUS | ES_SYSTEM_REQUIRED
        if not previous:
            raise OSError("SetThreadExecutionState failed; no hardware operation was started")
        self.previous = previous
        try:
            append(self.log_path, {"event": "system_awake_requested", "previous": previous,
                                   "flags": 0x80000001, "persistent_settings_changed": False})
        except BaseException:
            self.setter(previous | 0x80000000)
            self.previous = None
            raise
        return self

    def __exit__(self, exc_type, exc, traceback):
        if self.previous is not None:
            restored = self.setter(self.previous | 0x80000000)
            append(self.log_path, {"event": "system_awake_restored", "success": bool(restored),
                                   "previous": self.previous})
            if not restored and exc_type is None:
                raise OSError("Failed to restore the previous Windows execution state")
        return False

