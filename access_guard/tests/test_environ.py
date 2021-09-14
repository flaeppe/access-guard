import pytest
from starlette.config import EnvironError

from ..environ import Environ


class TestEnviron:
    def test_getitem_raises_environ_error_before_environ_has_been_loaded(self):
        with pytest.raises(EnvironError, match=r".*before environ has been loaded.*"):
            Environ({"something": "something"})["something"]

    def test_load_raises_environ_error_when_any_value_has_been_accessed(self):
        environ = Environ({})
        environ.load({"something": "something"})
        environ["something"]
        with pytest.raises(EnvironError, match=r".*when values has been read.*"):
            environ.load({})
