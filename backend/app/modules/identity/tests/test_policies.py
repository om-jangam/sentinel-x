from __future__ import annotations

import pytest

from app.core.errors import ValidationFailedError
from app.modules.identity.domain.policies import (
    normalize_email,
    validate_org_slug,
    validate_password,
    validate_role_name,
)


def test_normalize_email() -> None:
    assert normalize_email("  Ada@Example.COM ") == "ada@example.com"


def test_strong_passphrase_is_accepted() -> None:
    validate_password("correct-horse-battery-staple", email="ada@example.com")


@pytest.mark.parametrize(
    ("password", "fragment"),
    [
        ("short", "at least 12"),
        ("x" * 129, "at most 128"),
        ("aaaaaaaaaaaaaaaa", "distinct"),
        ("my-ada.lovelace-pw", "email name"),
    ],
)
def test_weak_passwords_are_rejected(password: str, fragment: str) -> None:
    with pytest.raises(ValidationFailedError) as info:
        validate_password(password, email="ada.lovelace@example.com" if "ada" in password else "x@example.com")
    assert any(fragment in e["msg"] for e in info.value.errors)
    assert all("input" not in e for e in info.value.errors), "never echo the password back"


@pytest.mark.parametrize("name", ["tier1_analyst", "abc", "soc_lead_2"])
def test_valid_role_names(name: str) -> None:
    validate_role_name(name)


@pytest.mark.parametrize("name", ["ab", "Admin", "1abc", "has-dash", "x" * 65])
def test_invalid_role_names(name: str) -> None:
    with pytest.raises(ValidationFailedError):
        validate_role_name(name)


def test_org_slug() -> None:
    validate_org_slug("acme-soc")
    with pytest.raises(ValidationFailedError):
        validate_org_slug("Acme SOC")
