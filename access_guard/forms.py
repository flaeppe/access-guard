from __future__ import annotations

import re
from typing import Any, Sequence

from pydantic import BaseModel, root_validator, validator
from pydantic.errors import PydanticValueError
from pydantic.networks import EmailStr

from .schema import LoginSignature

VERIFICATION_CODE_REGEX = re.compile(r"^\d{6}$")


class InvalidCode(PydanticValueError):
    code = "invalid"
    msg_template = "code is invalid"


class SendEmailForm(BaseModel):
    email: EmailStr

    def matches_patterns(self, patterns: Sequence[re.Pattern]) -> bool:
        for pattern in patterns:
            if pattern.match(self.email):
                return True

        return False


class VerificationForm(BaseModel):
    email: EmailStr
    code: str
    signature: str

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
