import secrets
import string

from itsdangerous.exc import BadData

from . import settings

CSRF_ALLOWED_CHARS = string.ascii_letters + string.digits
CSRF_TOKEN_LENGTH = 32
CSRF_COOKIE_NAME = "_csrftoken"
CSRF_COOKIE_MAX_AGE = 3600  # 1 hour


def get_token() -> tuple[str, str]:
    value = "".join(
        secrets.choice(CSRF_ALLOWED_CHARS) for __ in range(CSRF_TOKEN_LENGTH)
    )
    __, signature = (
        dumped
        if isinstance((dumped := settings.SIGNING.url_safe.dumps(value)), str)
        else dumped.decode()
    ).rsplit(settings.SIGNING.separator, 1)
    return value, signature


def does_token_match(body_csrf: str, cookie_csrf: str) -> bool:
    serializer = settings.SIGNING.url_safe
    try:
        csrf_token = serializer.loads(
            settings.SIGNING.separator.join(
                [serializer.dump_payload(body_csrf).decode(), cookie_csrf]
            )
        )
    except (ValueError, TypeError, BadData):
        return False

    return secrets.compare_digest(body_csrf, csrf_token)
