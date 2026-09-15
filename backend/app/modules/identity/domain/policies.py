"""Identity invariants: credential policy and naming rules."""

from __future__ import annotations

import re

from app.core.errors import ValidationFailedError

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
MIN_DISTINCT_CHARACTERS = 6

_ROLE_NAME = re.compile(r"[a-z][a-z0-9_]{2,63}")
_ORG_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{1,62}")


def normalize_email(email: str) -> str:
    return email.strip().lower()


def validate_password(password: str, *, email: str) -> None:
    """Length-first policy per NIST SP 800-63B: no composition rules, reject trivially weak values."""
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        problems.append(f"must be at most {MAX_PASSWORD_LENGTH} characters")
    if len(set(password)) < MIN_DISTINCT_CHARACTERS:
        problems.append(f"must contain at least {MIN_DISTINCT_CHARACTERS} distinct characters")
    local_part = normalize_email(email).split("@", 1)[0]
    if len(local_part) >= 3 and local_part in password.lower():
        problems.append("must not contain the account's email name")
    if problems:
        raise ValidationFailedError(
            "Password does not meet the password policy",
            errors=[{"loc": ["password"], "msg": p, "type": "password_policy"} for p in problems],
        )


def validate_role_name(name: str) -> None:
    if not _ROLE_NAME.fullmatch(name):
        raise ValidationFailedError(
            "Invalid role name",
            errors=[
                {
                    "loc": ["name"],
                    "msg": "lowercase letters, digits and underscores; 3-64 characters",
                    "type": "role_name",
                }
            ],
        )


def validate_org_slug(slug: str) -> None:
    if not _ORG_SLUG.fullmatch(slug):
        raise ValidationFailedError("Org slug must be lowercase letters, digits and hyphens")
