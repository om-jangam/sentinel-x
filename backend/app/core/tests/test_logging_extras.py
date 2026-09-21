"""Structured-log `extra` keys must not collide with LogRecord attributes.

`logging` raises KeyError for a colliding key, but only when the level is enabled. Tests run with INFO
disabled, so a collision would pass the suite and then fail in production inside whatever called it,
for example a bus handler whose message would never be acknowledged.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

APP = Path(__file__).resolve().parents[2]
RESERVED = set(vars(logging.LogRecord("name", logging.INFO, "path", 1, "msg", None, None))) | {"message", "asctime"}


def _extra_keys() -> list[tuple[str, int, str]]:
    found: list[tuple[str, int, str]] = []
    for path in APP.rglob("*.py"):
        if "tests" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg == "extra" and isinstance(keyword.value, ast.Dict):
                    for key in keyword.value.keys:
                        if isinstance(key, ast.Constant) and isinstance(key.value, str):
                            found.append((str(path.relative_to(APP)), node.lineno, key.value))
    return found


def test_log_extras_never_shadow_log_record_attributes() -> None:
    keys = _extra_keys()
    assert keys, "the scan found no structured log calls; it is probably looking in the wrong place"
    collisions = [f"{path}:{line} uses reserved key '{key}'" for path, line, key in keys if key in RESERVED]
    assert collisions == []
