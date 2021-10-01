from unittest import mock

import pytest
from itsdangerous.exc import BadData, BadSignature, SignatureExpired
from pydantic.error_wrappers import ValidationError

from .. import settings
from ..schema import (
    ForwardHeaders,
    InvalidForwardHeader,
    LoginSignature,
    PartialSignature,
    Verification,
)
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
        ),
    )
    def test_is_valid_returns_false_on(self, Error: type[Exception]) -> None:
        with mock.patch.object(settings.SIGNING.timed, "loads", autospec=True) as loads:
            loads.side_effect = Error("itsbad")
            result = LoginSignature.is_valid(
                email="someone@email.com", code="123456", signature="something"
            )

        assert result is False

    def test_has_valid_code_returns_false_when_code_is_invalid(self):
        login_signature = LoginSignature.create(
            email="someone@email.com", valid_code=False
        )
        assert login_signature.has_valid_code is False
        assert login_signature.code == "invalid"


class TestPartialSignature:
    @pytest.mark.parametrize(
        "Error",
        (
            pytest.param(BadData, id="bad data"),
            pytest.param(ValueError, id="value error"),
            pytest.param(TypeError, id="type error"),
        ),
    )
    def test_raises_validation_error_on(self, Error: type[Exception]) -> None:
        mock_serializer_loads = mock.patch.object(
            settings.SIGNING.timed.serializer, "loads", autospec=True
        )
        with mock_serializer_loads as loads, pytest.raises(ValidationError):
            loads.side_effect = Error("itsbad")
            PartialSignature.url_decode("something")


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
