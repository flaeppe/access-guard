import factory

from ..server import ForwardHeaders


class ForwardHeadersFactory(factory.Factory):
    method = "GET"
    proto = "http"
    host = "testservice.local"
    uri = "/"
    source = "172.29.0.1"

    class Meta:
        model = ForwardHeaders
