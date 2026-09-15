"""UUID v7 identifiers (RFC 9562): globally unique and time-sortable (docs/05 §2.3).

Python 3.12 has no `uuid.uuid7`, so we generate them here. Within one process the values are
strictly monotonic: a 12-bit counter in `rand_a` (RFC 9562 §6.2, method 1) disambiguates ids
created in the same millisecond.
"""

from __future__ import annotations

import os
import threading
import time
import uuid

_lock = threading.Lock()
_last_ms = 0
_counter = 0
_COUNTER_MAX = 0xFFF


def uuid7() -> uuid.UUID:
    global _last_ms, _counter
    with _lock:
        now_ms = time.time_ns() // 1_000_000
        if now_ms > _last_ms:
            _last_ms = now_ms
            # Random start leaves headroom for same-millisecond increments.
            _counter = int.from_bytes(os.urandom(2), "big") & 0x3FF
        else:
            _counter += 1
            if _counter > _COUNTER_MAX:
                _last_ms += 1
                _counter = 0
        ms, counter = _last_ms, _counter

    rand_b = int.from_bytes(os.urandom(8), "big") & ((1 << 62) - 1)
    value = (
        (ms & ((1 << 48) - 1)) << 80
        | 0x7 << 76  # version
        | counter << 64
        | 0b10 << 62  # variant
        | rand_b
    )
    return uuid.UUID(int=value)
