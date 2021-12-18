from typing import Any

import factory

from ..schema import ForwardHeaders


class ForwardHeadersFactory(factory.Factory):
    method = "GET"
    proto = "http"
    host = "example.com"
    uri = "/"
    source = "172.29.0.1"

    class Meta:
        model = ForwardHeaders

    @classmethod
    def _create(
        cls, model_class: type[ForwardHeaders], *args: Any, **kwargs: Any
    ) -> ForwardHeaders:
        return model_class.construct(*args, **kwargs)
