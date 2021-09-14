from typing import Any, MutableMapping

from starlette.config import Environ as StarletteEnviron, EnvironError


class Environ(StarletteEnviron):
    def __init__(self, environ: MutableMapping) -> None:
        super().__init__(environ)
        self._has_been_loaded = False

    def __getitem__(self, key: Any) -> Any:
        if not self._has_been_loaded:
            raise EnvironError(
                f"Accessing a value ({key}) before environ has been loaded is"
                " not permitted"
            )
        return super().__getitem__(key)

    def load(self, new: MutableMapping) -> None:
        if bool(self._has_been_read):
            keys = ",".join(self._has_been_read)
            raise EnvironError(
                f"Attempting to reload environment when values has been read ({keys})"
            )

        self._environ = new
        self._has_been_read = set()
        self._has_been_loaded = True


environ = Environ({})
