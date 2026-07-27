import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "_fixtures"


@pytest.fixture
def fixtures():
    return FIXTURES


def load_fixture(*parts):
    return json.loads((FIXTURES.joinpath(*parts)).read_text())
