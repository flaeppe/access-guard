from __future__ import annotations

import functools

from itsdangerous.exc import BadData, SignatureExpired
from pydantic.error_wrappers import ValidationError
from starlette.requests import Request
from starlette.responses import Response

from .. import settings
from ..log import logger
from ..schema import ForwardHeaders


class TamperedAuthCookie(Exception):
    ...


class IncompatibleAuthCookie(Exception):
    ...


def validate_auth_cookie(request: Request) -> ForwardHeaders | None:
    cookie = request.cookies.get(settings.AUTH_COOKIE_NAME)
    try:
        return ForwardHeaders.decode(cookie) if cookie else None
    except SignatureExpired as exc:
        # We'll simulate an expired cookie signature as an expired cookie
        # thus allowing for generating a new one
        date_signed = exc.date_signed.isoformat() if exc.date_signed else "--"
        logger.info("validate_auth_cookie.signature_expired %s", date_signed)
        return None
    except BadData as exc:
        logger.warning("validate_auth_cookie.tampered", exc_info=True)
        raise TamperedAuthCookie from exc
    except ValidationError as exc:
        logger.error(
            "validate_auth_cookie.incompatible_signature_payload %s",
            cookie,
            exc_info=True,
        )
        raise IncompatibleAuthCookie from exc


def set_cookie(response: Response, key: str, value: str, ttl: int) -> None:
    response.set_cookie(
        key=key,
        value=value,
        max_age=ttl,
        expires=ttl,
        domain=settings.COOKIE_DOMAIN,
        secure=settings.COOKIE_SECURE,
        httponly=True,
    )


set_auth_cookie = functools.partial(
    set_cookie, key=settings.AUTH_COOKIE_NAME, ttl=settings.AUTH_COOKIE_MAX_AGE
)
set_verified_cookie = functools.partial(
    set_cookie, key=settings.VERIFIED_COOKIE_NAME, ttl=settings.VERIFY_SIGNATURE_MAX_AGE
)
