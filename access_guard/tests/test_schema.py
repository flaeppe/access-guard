from typing import Any
from unittest import mock

import pytest
from itsdangerous.exc import BadData, BadSignature, SignatureExpired
from pydantic.error_wrappers import ValidationError

from .. import settings
from ..schema import ForwardHeaders, LoginSignature, Verification
from .factories import ForwardHeadersFactory

mock_time_signer_loads = mock.patch.object(
    settings.SIGNING.timed, "loads", autospec=True
)


class TestForwardHeaders:
    @pytest.mark.parametrize(
        "changes,error",
        (
            pytest.param(
                {"x-forwarded-method": "invalid"},
                [
                    {
                        "loc": ("x-forwarded-method",),
                        "ctx": {
                            "given": "invalid",
                            "permitted": (
                                "GET",
                                "HEAD",
                                "POST",
                                "PUT",
                                "DELETE",
                                "CONNECT",
                                "OPTIONS",
                                "TRACE",
                                "PATCH",
                            ),
                        },
                        "msg": (
                            "unexpected value; permitted: 'GET', 'HEAD', 'POST', 'PUT',"
                            " 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'"
                        ),
                        "type": "value_error.const",
                    }
                ],
                id="non http method",
            ),
            pytest.param(
                {"x-forwarded-proto": "invalid"},
                [
                    {
                        "loc": ("x-forwarded-proto",),
                        "ctx": {"given": "invalid", "permitted": ("http", "https")},
                        "msg": "unexpected value; permitted: 'http', 'https'",
                        "type": "value_error.const",
                    }
                ],
                id="invalid http protocol",
            ),
        ),
    )
    def test_raises_invalid_forward_header_on(
        self, changes: dict[str, str], error: list[dict]
    ) -> None:
        forward_headers = {
            "x-forwarded-method": "GET",
            "x-forwarded-proto": "http",
            "x-forwarded-host": "testservice.local",
            "x-forwarded-uri": "/",
            "x-forwarded-for": "172.29.0.1",
            **changes,
        }
        with pytest.raises(ValidationError) as exc:
            ForwardHeaders.parse_obj(forward_headers)

        assert exc.value.errors() == error

    def test_serialize_returns_aliased_names(self):
        forward_headers = ForwardHeadersFactory.create()
        assert forward_headers.serialize() == {
            "x-forwarded-method": forward_headers.method,
            "x-forwarded-proto": forward_headers.proto,
            "x-forwarded-host": forward_headers.host,
            "x-forwarded-uri": forward_headers.uri,
            "x-forwarded-for": forward_headers.source,
        }


class TestLoginSignature:
    @pytest.mark.parametrize(
        "Error",
        (
            pytest.param(BadData, id="bad data"),
            pytest.param(BadSignature, id="bad signature"),
            pytest.param(SignatureExpired, id="signature expired"),
        ),
    )
    def test_decode_returns_none_on_loads_raising(self, Error: type[Exception]) -> None:
        with mock.patch.object(settings.SIGNING.timed, "loads", autospec=True) as loads:
            loads.side_effect = Error("itsbad")
            result = LoginSignature.decode(signature="something")

        assert result is None
        loads.assert_called_once_with(
            "something", max_age=settings.LOGIN_SIGNATURE_MAX_AGE
        )

    @pytest.mark.parametrize(
        "payload",
        (
            pytest.param({}, id="payload missing expected keys"),
            pytest.param(["notamapping"], id="payload is not a mapping"),
            pytest.param({"email": "notanemail"}, id="payload has an invalid email"),
            pytest.param(
                {"email": "not@allowed.com"},
                id="email is not matching configured patterns",
            ),
        ),
    )
    def test_decode_returns_none_when(self, payload: Any) -> None:
        signature = settings.SIGNING.timed.dumps(payload)
        assert LoginSignature.decode(signature) is None


class TestVerification:
    @pytest.mark.parametrize(
        "error",
        (
            pytest.param(SignatureExpired("expired"), id="signature expired"),
            pytest.param(BadData("bad data"), id="bad data"),
        ),
    )
    def test_decode_returns_none_when_loads_raises(self, error: Exception) -> None:
        with mock_time_signer_loads as loads:
            loads.side_effect = error
            assert Verification.decode("signature") is None

        loads.assert_called_once_with(
            "signature", max_age=settings.VERIFY_SIGNATURE_MAX_AGE
        )

    @pytest.mark.parametrize(
        "signature",
        (
            pytest.param(
                settings.SIGNING.timed.dumps({"email": "notanemail"}),
                id="invalid email",
            ),
            pytest.param("", id="empty signature"),
        ),
    )
    def test_decode_returns_none_on_invalid_email(self, signature: str) -> None:
        assert Verification.decode(signature) is None

    def test_check_returns_false_on_undecodable_signature(self) -> None:
        assert Verification.check("") is False

    def test_check_returns_false_on_signature_email_not_matching_configured_patterns(
        self,
    ) -> None:
        signature = settings.SIGNING.timed.dumps({"email": "mismatch@email.com"})
        assert Verification.check(signature) is False
