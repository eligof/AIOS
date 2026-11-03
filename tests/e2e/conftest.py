"""pytest setup for tests/e2e: ordered e2e steps and the --keep-vm option."""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--keep-vm",
        action="store_true",
        help="keep the VM disk and TPM state in build/e2e after a passing run too"
        " (a failed run always keeps them; the firmware variables and transcript stay anyway)",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "incremental: later tests in the module xfail once one test fails"
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):
    outcome = yield
    report = outcome.get_result()
    if "incremental" not in item.keywords:
        return
    if call.when == "call" and call.excinfo is not None:
        item.parent._aios_failed = item.name  # type: ignore[attr-defined]
    if call.when == "call" and report.passed:
        # The module's fixture deletes the VM disk only if all of its tests passed.
        item.parent._aios_passed = getattr(item.parent, "_aios_passed", 0) + 1  # type: ignore[attr-defined]


def pytest_runtest_setup(item: pytest.Item) -> None:
    if "incremental" in item.keywords:
        failed = getattr(item.parent, "_aios_failed", None)
        if failed is not None:
            pytest.xfail(f"an earlier step failed: {failed}")
