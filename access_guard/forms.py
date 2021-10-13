from pydantic import BaseModel, validator
from pydantic.networks import EmailStr

from .validators import DisallowedEmail, check_email_is_allowed


class SendEmailForm(BaseModel):
    email: EmailStr

    # It's a bit sad that pydantic doesn't accept `str.lower` directly as validator..
    _normalize_email = validator("email", always=True)(lambda value: value.lower())

    @property
    def has_allowed_email(self) -> bool:
        # We avoid having this as a pydantic validator as checking against configured
        # email patterns is wanted at a stage later than during BaseModel validation
        try:
            check_email_is_allowed(self.email)
            return True
        except DisallowedEmail:
            return False
