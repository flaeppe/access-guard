from unittest import mock

import pytest

from ..validators import DisallowedEmail, check_email_is_allowed


class TestCheckEmailIsAllowed:
    @pytest.mark.parametrize(
        "email",
        (
            pytest.param(
                "mismatch@email.com", id="when email doesn't match configured patterns"
            ),
            pytest.param("", id="when empty string"),
        ),
    )
    def test_raises_disallowed_email(self, email: str) -> None:
        with pytest.raises(DisallowedEmail):
            check_email_is_allowed(email)

    def test_raises_disallowed_email_when_no_patterns_configured(self) -> None:
        mock_configured_patterns = mock.patch(
            "access_guard.validators.settings.EMAIL_PATTERNS", []
        )
        with pytest.raises(DisallowedEmail), mock_configured_patterns:
            check_email_is_allowed("someone@test.com")
