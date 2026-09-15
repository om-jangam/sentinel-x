from __future__ import annotations

import pytest

from app.core.errors import ValidationFailedError
from app.core.ids import uuid7
from app.core.pagination import decode_cursor, encode_cursor


def test_uuid7_version_variant_and_monotonicity() -> None:
    ids = [uuid7() for _ in range(5000)]
    assert all(u.version == 7 for u in ids)
    assert all((u.int >> 62) & 0b11 == 0b10 for u in ids)
    assert ids == sorted(ids), "uuid7 must be strictly time-ordered within a process"
    assert len(set(ids)) == len(ids)


def test_cursor_round_trip() -> None:
    assert decode_cursor(encode_cursor("0192-abc")) == "0192-abc"


@pytest.mark.parametrize("bad", ["***", "éé"])
def test_malformed_cursor_is_a_validation_error(bad: str) -> None:
    with pytest.raises(ValidationFailedError):
        decode_cursor(bad)
