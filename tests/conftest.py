"""Keep parametrized case IDs portable and out of environment-variable size limits."""

import pytest


def pytest_collection_modifyitems(items):
    if any(len(item.nodeid) > 4096 for item in items):
        raise pytest.UsageError(
            "Test ID exceeds 4096 characters; use explicit short ids for large input fixtures"
        )
