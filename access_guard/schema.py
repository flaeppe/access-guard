from __future__ import annotations

from collections import abc
from typing import TYPE_CHECKING, Any, ClassVar, Literal, TypeVar

from itsdangerous.exc import BadData, SignatureExpired
from pydantic import BaseModel, Field, validator
from pydantic.error_wrappers import ValidationError
from pydantic.networks import EmailStr

from . import settings
from .log import logger
from .validators import check_email_is_allowed

if TYPE_CHECKING:
    DecodableParent = BaseModel
else:
    DecodableParent = object


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
        return encoded if isinstance(encoded, str) else encoded.decode()


T = TypeVar("T", bound="Decodable")


class Decodable(DecodableParent):
    MAX_AGE: ClassVar[int]

    @classmethod
    def decode(cls, signature: str) -> abc.MutableMapping | None:
        if not signature:
            return None

        try:
            loaded = settings.SIGNING.timed.loads(signature, max_age=cls.MAX_AGE)
        except SignatureExpired as exc:
            date_signed = exc.date_signed.isoformat() if exc.date_signed else "--"
            logger.info("decodable.decode.expired %s", date_signed)
            return None
        except BadData:
            logger.warning("decodable.decode.bad_data", exc_info=True)
            return None

        if not isinstance(loaded, abc.MutableMapping):
            # TODO: Log received type (type=type(loaded))
            logger.error("decodable.decode.payload_type_invalid")
            return None
        return loaded

    @classmethod
    def loads(cls: type[T], signature: str) -> T | None:
        decoded = cls.decode(signature)
        if decoded is None:
            return None

        try:
            return cls.parse_obj(decoded)
        except ValidationError:
            logger.error("decodable.loads.invalid_payload", exc_info=True)
            return None


class LoginSignature(Decodable, BaseModel):
    email: EmailStr
    signature: str

    _validate_email = validator("email", allow_reuse=True, always=True)(
        check_email_is_allowed
    )

    MAX_AGE: ClassVar[int] = settings.LOGIN_SIGNATURE_MAX_AGE

    @classmethod
    def create(cls, email: str) -> LoginSignature:
        signature = settings.SIGNING.timed.dumps({"email": email})
        return cls(
            email=email,
            signature=signature if isinstance(signature, str) else signature.decode(),
        )

    @classmethod
    def decode(cls, signature: str) -> abc.MutableMapping | None:
        decoded = super().decode(signature)
        if decoded is not None:
            decoded["signature"] = signature
        return decoded


class Verification(LoginSignature):
    MAX_AGE: ClassVar[int] = settings.VERIFY_SIGNATURE_MAX_AGE

    @classmethod
    def check(cls, signature: str) -> bool:
        return bool(cls.loads(signature))
