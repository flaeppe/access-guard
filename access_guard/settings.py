from __future__ import annotations

import hashlib
import re
from pathlib import Path
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
SECRET: Secret = config("secret", cast=Secret)
DOMAIN: str = config("auth_host", cast=str)
# TODO: AUTH_TOKEN = config("auth_token", cast=Secret)
COOKIE_DOMAIN: str = config("cookie_domain", cast=str)
COOKIE_SECURE: bool = config("cookie_secure", cast=bool, default=False)
LOGIN_COOKIE_NAME: str = config("login_cookie_name", cast=str)
VERIFIED_COOKIE_NAME: str = config("verified_cookie_name", cast=str)

# Email config
EMAIL_HOST: str = config("email_host", cast=str)
EMAIL_PORT: int = config("email_port", cast=int)
FROM_EMAIL: str = config("from_email", cast=str)
EMAIL_USERNAME: str | None = config("email_username", cast=str, default=None)
EMAIL_PASSWORD: Secret | None = config("email_password", cast=Secret, default=None)
EMAIL_USE_TLS: bool = config("email_use_tls", cast=bool, default=False)
EMAIL_START_TLS: bool = config("email_start_tls", cast=bool, default=False)
EMAIL_VALIDATE_CERTS: bool = config("email_validate_certs", cast=bool, default=True)
EMAIL_CLIENT_CERT: Path | None = config("email_client_cert", cast=Path, default=None)
EMAIL_CLIENT_KEY: Path | None = config("email_client_key", cast=Path, default=None)
EMAIL_SUBJECT: str = config("email_subject", cast=str)

HOST: str = config("host", cast=str, default="0.0.0.0")  # nosec
PORT: int = config("port", cast=int, default=8585)
DEBUG: bool = config("debug", cast=bool, default=False)


class Signers(NamedTuple):
    timed: URLSafeTimedSerializer
    separator: str


SIGNING = Signers(
    timed=URLSafeTimedSerializer(
        str(SECRET),
        salt="access_guard.signing.timed",
        signer_kwargs={"sep": ".", "digest_method": hashlib.sha256},
    ),
    separator=".",
)


LOGIN_COOKIE_MAX_AGE = 60 * 60  # 1 hour
LOGIN_SIGNATURE_MAX_AGE = 60 * 10  # 10 min
VERIFY_SIGNATURE_MAX_AGE = 60 * 60 * 24  # 24 hours
