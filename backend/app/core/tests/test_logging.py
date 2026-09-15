from __future__ import annotations

import json
import logging
import sys

from app.core.observability.context import correlation_id_var
from app.core.observability.logging import JsonFormatter, configure_logging


def test_json_formatter_includes_correlation_id_and_structured_extras() -> None:
    token = correlation_id_var.set("cid-123")
    try:
        record = logging.makeLogRecord(
            {"name": "sx", "levelname": "INFO", "msg": "hello %s", "args": ("world",), "audit_action": "user.created"}
        )
        payload = json.loads(JsonFormatter().format(record))
    finally:
        correlation_id_var.reset(token)
    assert payload["message"] == "hello world"
    assert payload["correlation_id"] == "cid-123"
    assert payload["audit_action"] == "user.created"


def test_json_formatter_serialises_exceptions() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        record = logging.getLogger("sx").makeRecord("sx", logging.ERROR, __file__, 1, "failed", (), sys.exc_info())
    payload = json.loads(JsonFormatter().format(record))
    assert "ValueError: boom" in payload["exception"]


def test_configure_logging_installs_a_single_handler() -> None:
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    try:
        configure_logging(level="warning", json_output=True)
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, JsonFormatter)
        assert root.level == logging.WARNING
        configure_logging(level="info", json_output=False)
        assert not isinstance(root.handlers[0].formatter, JsonFormatter)
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
