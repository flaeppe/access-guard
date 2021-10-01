from pydantic.errors import PydanticValueError

from . import settings


class DisallowedEmail(PydanticValueError):
    code = "disallowed"
    msg_template = "email is not allowed"


def check_email_is_allowed(email: str) -> str:
    for pattern in settings.EMAIL_PATTERNS:
        if pattern.match(email):
            return email

    raise DisallowedEmail
