from __future__ import annotations

import hashlib
import re
from typing import Any, NamedTuple, Sequence

from itsdangerous.url_safe import URLSafeTimedSerializer
from starlette.config import Config
from starlette.datastructures import Secret

from .environ import environ

config = Config(environ=environ)


def as_regex_patterns(str_patterns: Sequence[Any]) -> Sequence[re.Pattern]:
    return tuple(
        (re.compile(pattern) if not isinstance(pattern, re.Pattern) else pattern)
        for pattern in str_patterns
    )


EMAIL_PATTERNS: Sequence[re.Pattern] = config("email_patterns", cast=as_regex_patterns)
SECRET = config("secret", cast=Secret)
DOMAIN = config("auth_host", cast=str)
# TODO: AUTH_TOKEN = config("auth_token", cast=Secret)
COOKIE_DOMAIN = config("cookie_domain", cast=str)

EMAIL_HOST = config("email_host", cast=str)
EMAIL_PORT = config("email_port", cast=int)
FROM_EMAIL = config("from_email", cast=str)
# TODO: Support these for email?
# username: str | None
# password: Secret | None
# timeout: float | None
# ssl: bool | None
# tls: bool | None
# validate_certs: bool | None

HOST = config("host", cast=str, default="0.0.0.0")  # nosec
PORT = config("port", cast=int, default=8585)
DEBUG = config("debug", cast=bool, default=False)


class Signers(NamedTuple):
    timed: URLSafeTimedSerializer
    separator: str


SIGNING = Signers(
    timed=URLSafeTimedSerializer(
        str(SECRET),
        # TODO: Change salt
        # salt="access_guard.signing.timed",
        salt="access_guard.config",
        signer_kwargs={"sep": ".", "digest_method": hashlib.sha256},
    ),
    separator=".",
)


LOGIN_COOKIE_MAX_AGE = 60 * 60  # 1 hour
LOGIN_SIGNATURE_MAX_AGE = 60 * 10  # 10 min
VERIFY_SIGNATURE_MAX_AGE = 60 * 60 * 24  # 24 hours
