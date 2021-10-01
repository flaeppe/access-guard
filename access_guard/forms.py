from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, root_validator, validator
from pydantic.errors import PydanticValueError
from pydantic.networks import EmailStr

from .schema import LoginSignature
from .validators import DisallowedEmail, check_email_is_allowed

VERIFICATION_CODE_REGEX = re.compile(r"^\d{6}$")


class InvalidCode(PydanticValueError):
    code = "invalid"
    msg_template = "code is invalid"


class SendEmailForm(BaseModel):
    email: EmailStr

    @property
    def has_allowed_email(self) -> bool:
        # We avoid having this as a pydantic validator as checking against configured
        # email patterns is wanted at a stage later than during BaseModel validation
        try:
            check_email_is_allowed(self.email)
            return True
        except DisallowedEmail:
            return False


class VerificationForm(BaseModel):
    email: EmailStr
    code: str
    signature: str

    _validate_email = validator("email", allow_reuse=True, always=True)(
        check_email_is_allowed
    )

    @validator("code", always=True)
    def _validate_code(cls, code: str) -> str:
        if not VERIFICATION_CODE_REGEX.match(code):
            raise InvalidCode
        return code

    @root_validator(skip_on_failure=True)
    def validate_signature(cls, values: dict[str, Any]) -> dict[str, Any]:
        is_valid = LoginSignature.is_valid(
            email=values["email"], code=values["code"], signature=values["signature"]
        )
        if is_valid:
            return values

        raise InvalidCode
