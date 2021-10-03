from typing import Any
from unittest import mock

import pytest
from itsdangerous.exc import BadData, BadSignature, SignatureExpired

from .. import settings
from ..schema import ForwardHeaders, InvalidForwardHeader, LoginSignature, Verification
from .factories import ForwardHeadersFactory

mock_time_signer_loads = mock.patch.object(
    settings.SIGNING.timed, "loads", autospec=True
)


class TestForwardHeaders:
    @pytest.mark.parametrize(
        "changes",
        (
            pytest.param({"method": "invalid"}, id="non http method"),
            pytest.param({"proto": "invalid"}, id="invalid http protocol"),
        ),
    )
    def test_raises_invalid_forward_header_on(self, changes: dict[str, str]) -> None:
        forward_headers = ForwardHeadersFactory(**changes).serialize()
        with pytest.raises(InvalidForwardHeader):
            ForwardHeaders.parse(forward_headers)


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
