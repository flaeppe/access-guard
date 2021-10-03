import pytest
from pydantic.error_wrappers import ValidationError

from ..forms import SendEmailForm


class TestSendEmailForms:
    def test_raises_validation_error_with_invalid_email(self) -> None:
        with pytest.raises(ValidationError) as exc:
            SendEmailForm.parse_obj({"email": "!@dlkfjs@email.com"})

        assert exc.value.errors() == [
            {
                "loc": ("email",),
                "msg": "value is not a valid email address",
                "type": "value_error.email",
            },
        ]
