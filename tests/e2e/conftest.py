"""pytest setup for tests/e2e: ordered e2e steps and the --keep-vm option."""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--keep-vm",
        action="store_true",
        help="leave build/e2e (disk, firmware variables, transcript) for inspection",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "incremental: later tests in the module xfail once one test fails"
    )


def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> None:
    if "incremental" in item.keywords and call.excinfo is not None and call.when == "call":
        item.parent._aios_failed = item.name  # type: ignore[attr-defined]


def pytest_runtest_setup(item: pytest.Item) -> None:
    if "incremental" in item.keywords:
        failed = getattr(item.parent, "_aios_failed", None)
        if failed is not None:
            pytest.xfail(f"an earlier step failed: {failed}")
