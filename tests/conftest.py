import sys
from collections.abc import Generator
from pathlib import Path

import pytest

# Ensure src/ is on the import path for tests (avoids relying on install)
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(autouse=True)
def _ensure_src_path() -> Generator[None]:
    """No-op fixture to keep autouse in place."""
    yield
