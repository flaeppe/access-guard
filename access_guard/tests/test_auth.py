from functools import partial
from http import HTTPStatus
from unittest import mock

from starlette.datastructures import URL

from ..routes.auth import start_verification_response
from .factories import ForwardHeadersFactory


class TestStartVerificationResponse:
    mock_auth_host = partial(
        mock.patch, "access_guard.routes.auth.settings.AUTH_HOST", new_callable=URL
    )

    def test_extends_auth_host_path(self):
        forward_headers = ForwardHeadersFactory()
        with self.mock_auth_host(url="http://example.com/some/path/"):
            response = start_verification_response(forward_headers)

        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == "http://example.com/some/path/send"

    def test_uses_protocol_from_forward_headers(self):
        forward_headers = ForwardHeadersFactory(proto="https")
        with self.mock_auth_host(url="http://example.com/some/path/"):
            response = start_verification_response(forward_headers)

        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == "https://example.com/some/path/send"
