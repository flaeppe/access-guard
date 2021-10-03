from __future__ import annotations

import logging
from collections import abc
from typing import Any, Literal

from itsdangerous.exc import BadData, SignatureExpired
from pydantic import BaseModel, Field, validator
from pydantic.error_wrappers import ValidationError
from pydantic.networks import EmailStr

from . import settings
from .validators import check_email_is_allowed

logger = logging.getLogger(__name__)


HTTPMethod = Literal[
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"
]
HTTP_METHODS: set[HTTPMethod] = {
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH",
}


class ForwardHeaders(BaseModel):
    method: HTTPMethod = Field(alias="x-forwarded-method")
    proto: Literal["http", "https"] = Field(alias="x-forwarded-proto")
    host: str = Field(alias="x-forwarded-host")
    uri: str = Field(alias="x-forwarded-uri")
    source: str = Field(alias="x-forwarded-for")

    @classmethod
    def decode(cls, value: str) -> ForwardHeaders:
        # TODO: Set a different max age from cookie (should be longer per default?)
        loaded = settings.SIGNING.timed.loads(
            value, max_age=settings.LOGIN_COOKIE_MAX_AGE
        )
        return cls.parse_obj(loaded)

    @property
    def url_unparsed(self) -> str:
        return f"{self.proto}://{self.host}{self.uri}"

    def serialize(self) -> dict[str, Any]:
        return self.dict(by_alias=True)

    def encode(self) -> str:
        encoded = settings.SIGNING.timed.dumps(self.serialize())
        assert isinstance(encoded, str)
        return encoded


class LoginSignature(BaseModel):
    email: EmailStr
    signature: str

    _validate_email = validator("email", allow_reuse=True, always=True)(
        check_email_is_allowed
    )

    @classmethod
    def create(cls, email: str) -> LoginSignature:
        signature = settings.SIGNING.timed.dumps({"email": email})
        assert isinstance(signature, str)
        return cls(email=email, signature=signature)

    @classmethod
    def decode(cls, signature: str) -> LoginSignature | None:
        # TODO: DRY unsigning for reusage with Verification
        try:
            loaded = settings.SIGNING.timed.loads(
                signature, max_age=settings.LOGIN_SIGNATURE_MAX_AGE
            )
        except SignatureExpired as exc:
            date_signed = exc.date_signed.isoformat() if exc.date_signed else "--"
            logger.info("login_signature.decode.expired %s", date_signed)
            return None
        except BadData:
            logger.warning("login_signature.decode.bad_data", exc_info=True)
            return None

        if not isinstance(loaded, abc.MutableMapping):
            # TODO: Log received type (type=type(loaded))
            logger.error("login_signature.decode.payload_not_a_mapping")
            return None

        loaded["signature"] = signature
        try:
            return cls.parse_obj(loaded)
        except ValidationError:
            logger.error("login_signature.decode.invalid_payload", exc_info=True)
            return None


class Verification(BaseModel):
    email: EmailStr

    _validate_email = validator("email", allow_reuse=True, always=True)(
        check_email_is_allowed
    )

    @classmethod
    def decode(cls, signature: str) -> Verification | None:
        if not signature:
            return None

        # TODO: DRY unsigning for reusage with LoginSignature
        try:
            return cls.parse_obj(
                settings.SIGNING.timed.loads(
                    signature, max_age=settings.VERIFY_SIGNATURE_MAX_AGE
                )
            )
        except SignatureExpired as exc:
            date_signed = exc.date_signed.isoformat() if exc.date_signed else "--"
            logger.debug("verification.decode.signature_expired %s", date_signed)
        except BadData:
            logger.warning("verification.decode.bad_data", exc_info=True)
        except ValidationError:
            logger.warning("verification.decode.invalid", exc_info=True)

        return None

    @classmethod
    def check(cls, signature: str) -> bool:
        return bool(cls.decode(signature))
