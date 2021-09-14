import pytest
from pydantic import BaseModel
from pydantic.error_wrappers import ValidationError

from ..forms import SendEmailForm, VerificationForm


@pytest.mark.parametrize(
    "Model",
    (SendEmailForm, VerificationForm),
    ids=["SendEmailForm", "VerificationForm"],
)
class TestEmailForms:
    def test_raises_validation_error_with_invalid_email(self, Model: BaseModel) -> None:
        # Working with BaseModel subsets works. As we can fill all fields for the
        # proper superset. Any unknown keys/fields will be ignored.
        data = {
            "email": "!@dlkfjs@email.com",
            "code": "000000",
            "signature": "something",
        }
        with pytest.raises(ValidationError) as exc:
            Model.parse_obj(data)

        assert exc.value.errors() == [
            {
                "loc": ("email",),
                "msg": "value is not a valid email address",
                "type": "value_error.email",
            },
        ]


class TestVerificationForm:
    @pytest.mark.parametrize(
        "code,msg,error_code",
        (
            pytest.param(
                "1234567",
                "code is invalid",
                "value_error.invalid",
                id="more than 6 digits",
            ),
            pytest.param(
                "12345",
                "code is invalid",
                "value_error.invalid",
                id="less than 6 digits",
            ),
            pytest.param(
                "000a00",
                "code is invalid",
                "value_error.invalid",
                id="including characters",
            ),
            pytest.param(
                "", "code is invalid", "value_error.invalid", id="being empty"
            ),
            pytest.param(
                b"bytes", "code is invalid", "value_error.invalid", id="being bytes"
            ),
            pytest.param(
                None,
                "none is not an allowed value",
                "type_error.none.not_allowed",
                id="being none",
            ),
            pytest.param(
                object, "str type expected", "type_error.str", id="being object"
            ),
            pytest.param(
                True, "code is invalid", "value_error.invalid", id="being bool"
            ),
        ),
    )
    def test_raises_validation_error_on_code(
        self, code: str, msg: str, error_code: str
    ) -> None:
        data = {"email": "valid@email.com", "code": code, "signature": "something"}
        with pytest.raises(ValidationError) as exc:
            VerificationForm.parse_obj(data)

        assert exc.value.errors() == [
            {"loc": ("code",), "msg": msg, "type": error_code}
        ]

    def test_raises_validation_error_on_empty_data(self) -> None:
        with pytest.raises(ValidationError) as exc:
            VerificationForm.parse_obj({})

        assert exc.value.errors() == [
            {"loc": ("email",), "msg": "field required", "type": "value_error.missing"},
            {"loc": ("code",), "msg": "field required", "type": "value_error.missing"},
            {
                "loc": ("signature",),
                "msg": "field required",
                "type": "value_error.missing",
            },
        ]
