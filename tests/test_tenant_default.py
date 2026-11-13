"""Guards against the hardcoded ``n8n-dev`` / ``test_user`` tenant literals.

``n8n-dev`` was a *string*, not a tenant: any boundary that accepts an
arbitrary string is a licence to MINT a tenant, and the literal went on to
own hundreds of rows fleet-wide. The real tenant in the licence registry is
the uuid below (``platform-cp-1``).

The "literal is gone" assertion below is deliberately AST-based rather than a
``grep``. A text search over ``src/`` is trivially defeated: the comment
explaining the removal would itself match. Comments never reach the AST, and
docstrings are filtered out explicitly, so only real string *values* are
checked.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest
from pydantic import ValidationError

from auth import dependencies as auth_deps
from auth import middleware as auth_mw
from config import Settings

PLATFORM_TENANT_ID = "0195f48b-d000-7000-8000-000000000001"
BANNED_LITERALS = {"n8n-dev", "test_user"}

SRC = Path(__file__).resolve().parent.parent / "src"


def _string_values(tree: ast.AST) -> list[str]:
    """Every str constant in the module except docstrings."""
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstrings.add(id(body[0].value))
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def test_default_tenant_id_is_a_uuid() -> None:
    assert Settings().default_tenant_id == PLATFORM_TENANT_ID
    uuid.UUID(Settings().default_tenant_id)


def test_module_level_defaults_are_uuids() -> None:
    for value in (auth_mw.DEFAULT_TENANT_ID, auth_deps.DEFAULT_TENANT_ID):
        uuid.UUID(value)
        assert value == PLATFORM_TENANT_ID


def test_non_uuid_default_tenant_id_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(default_tenant_id="n8n-dev")


def test_banned_tenant_literals_are_absent_from_src() -> None:
    """No source file may contain the literals as *values* (comments excluded)."""
    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for value in _string_values(tree):
            if value in BANNED_LITERALS:
                offenders.append(f"{path.relative_to(SRC)}: {value!r}")
    assert not offenders, f"banned tenant literals still present: {offenders}"


def test_the_guard_itself_is_not_vacuous(tmp_path: Path) -> None:
    """The AST scan must see a value but ignore a comment/docstring mention."""
    sample = tmp_path / "sample.py"
    sample.write_text(
        '"""Removed the n8n-dev default."""\n# n8n-dev used to live here\nTENANT = "n8n-dev"\n',
        encoding="utf-8",
    )
    values = _string_values(ast.parse(sample.read_text(encoding="utf-8")))
    assert "n8n-dev" in values  # the assignment is seen
    assert values.count("n8n-dev") == 1  # docstring + comment are not
