from datetime import datetime
from typing import Any

import pytest

from .. import csrf


class TestDoesTokenMatch:
    @pytest.mark.parametrize(
        "value",
        (
            pytest.param(datetime(2021, 1, 1), id="type error"),
            pytest.param("abcdef", id="bad data"),
        ),
    )
    def test_returns_false_when_loading_signature_raises(self, value: Any) -> None:
        assert csrf.does_token_match(value, "other value") is False
