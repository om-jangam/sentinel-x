"""Each process entry point must register every ORM model, or cross-module foreign keys can't resolve.

The test suite imports everything through its fixtures, which hid this: the worker once failed every batch in
production with NoReferencedTableError ('orgs'). These run each entry point in a clean interpreter instead.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

CHECK = (
    "import importlib, sys; importlib.import_module(sys.argv[1]); "
    "from app.core.db.base import Base; "
    "wanted = {'orgs', 'users', 'findings', 'incidents', 'intel_results', 'incident_analyses'}; "
    "missing = wanted - set(Base.metadata.tables); "
    "sys.exit(f'missing tables: {sorted(missing)}' if missing else 0)"
)


# The CLI imports per command; its commands that touch the database go through these two or model_registry.
@pytest.mark.parametrize("entry_point", ["app.worker", "app.main"])
def test_entry_points_register_every_model(entry_point: str) -> None:
    result = subprocess.run(  # noqa: S603 - fixed interpreter and arguments
        [sys.executable, "-c", CHECK, entry_point], capture_output=True, text=True, timeout=120, check=False
    )
    assert result.returncode == 0, result.stderr or result.stdout
