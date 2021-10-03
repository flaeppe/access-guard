from pydantic import BaseModel
from pydantic.networks import EmailStr

from .validators import DisallowedEmail, check_email_is_allowed


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
