from typing import Any
from unittest import mock

import pytest
from itsdangerous.exc import BadData, BadSignature, SignatureExpired
from pydantic.error_wrappers import ValidationError

from .. import settings
from ..schema import AuthSignature, Decodable, ForwardHeaders, Verification
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

    @pytest.mark.parametrize(
        "value,expected",
        (
            pytest.param(
                "www.some-place.com:1337", "www.some-place.com", id="strips port"
            ),
            pytest.param("", "", id="handles empty"),
            pytest.param(
                "some-place", "some-place", id="does nothing when no port is specified"
            ),
        ),
    )
    def test_host_name(self, value: str, expected: str) -> None:
        assert ForwardHeadersFactory(host=value).host_name == expected


class DecodableClass(Decodable):
    MAX_AGE = 666


class TestDecodable:
    @pytest.mark.parametrize(
        "error",
        (
            pytest.param(BadData("baddata"), id="bad data"),
            pytest.param(BadSignature("badsignature"), id="bad signature"),
            pytest.param(SignatureExpired("expired"), id="signature expired"),
        ),
    )
    def test_decode_returns_none_when_signer_loads_raises(
        self, error: Exception
    ) -> None:
        with mock_time_signer_loads as loads:
            loads.side_effect = error
            result = DecodableClass.decode("doesnotmatter")

        assert result is None
        loads.assert_called_once_with("doesnotmatter", max_age=666)

    @pytest.mark.parametrize(
        "value",
        (
            pytest.param("", id="empty"),
            pytest.param(
                settings.SIGNING.timed.dumps(["not a mapping"]),
                id="payload is not a mapping",
            ),
        ),
    )
    def test_decode_returns_none_on_signature(self, value: str) -> None:
        assert DecodableClass.decode(value) is None


class TestAuthSignature:
    def test_signing_loads_is_called_with_auth_signature_max_age(self):
        signature = "doesnotmatter"
        with mock_time_signer_loads as loads:
            loads.return_value = {"email": "someone@test.com", "signature": signature}
            result = AuthSignature.loads(signature)

        assert result == AuthSignature(email="someone@test.com", signature=signature)
        loads.assert_called_once_with(
            signature, max_age=settings.AUTH_SIGNATURE_MAX_AGE
        )

    @pytest.mark.parametrize(
        "payload",
        (
            pytest.param({}, id="payload missing expected keys"),
            pytest.param({"email": "notanemail"}, id="payload has an invalid email"),
            pytest.param(
                {"email": "not@allowed.com"},
                id="email is not matching configured patterns",
            ),
        ),
    )
    def test_loads_returns_none_when(self, payload: Any) -> None:
        signature = settings.SIGNING.timed.dumps(payload)
        assert AuthSignature.loads(signature) is None


class TestVerification:
    def test_signing_loads_is_called_with_verify_signature_max_age(self):
        with mock_time_signer_loads as loads:
            loads.return_value = {"email": "someone@test.com"}
            result = Verification.loads("doesnotmatter")

        assert result == Verification(
            email="someone@test.com", signature="doesnotmatter"
        )
        loads.assert_called_once_with(
            "doesnotmatter", max_age=settings.VERIFY_SIGNATURE_MAX_AGE
        )

    @pytest.mark.parametrize(
        "payload",
        (
            pytest.param({}, id="payload missing expected keys"),
            pytest.param({"email": "notanemail"}, id="payload has an invalid email"),
            pytest.param(
                {"email": "not@allowed.com"},
                id="email is not matching configured patterns",
            ),
        ),
    )
    def test_loads_returns_none_when(self, payload: Any) -> None:
        signature = settings.SIGNING.timed.dumps(payload)
        assert Verification.loads(signature) is None

    def test_check_returns_false_when_loads_returns_none(self) -> None:
        with mock.patch.object(Verification, "loads", autospec=True) as loads:
            loads.return_value = None
            result = Verification.check("doesnotmatter")

        assert result is False
        loads.assert_called_once_with("doesnotmatter")
