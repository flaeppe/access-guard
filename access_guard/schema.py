from __future__ import annotations

import logging
import secrets
from collections import abc
from dataclasses import dataclass
from typing import Any, Literal, cast

from itsdangerous.encoding import (
    base64_decode as itsdangerous_base64_decode,
    base64_encode as itsdangerous_base64_encode,
)
from itsdangerous.exc import BadData, BadSignature
from pydantic import BaseModel
from pydantic.error_wrappers import ErrorWrapper, ValidationError
from pydantic.networks import EmailStr
from pydantic.utils import ROOT_KEY
from starlette.datastructures import Headers

from . import settings

logger = logging.getLogger(__name__)


class MissingForwardHeader(Exception):
    ...


class InvalidForwardHeader(Exception):
    ...


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


@dataclass(frozen=True)
class ForwardHeaders:
    method: HTTPMethod
    proto: Literal["http", "https"]
    host: str
    uri: str
    source: str

    @classmethod
    def parse(cls, headers: Headers) -> ForwardHeaders:
        try:
            forward_headers = {
                "method": headers["x-forwarded-method"],
                "proto": headers["x-forwarded-proto"],
                "host": headers["x-forwarded-host"],
                "uri": headers["x-forwarded-uri"],
                "source": headers["x-forwarded-for"],
            }
        except KeyError as exc:
            logger.debug("forward_headers.parse.missing_header", exc_info=exc)
            raise MissingForwardHeader from exc

        method = forward_headers["method"] or ""
        if method.upper() not in HTTP_METHODS:
            logger.debug("forward_headers.parse.invalid_method '%s'", method)
            raise InvalidForwardHeader
        proto = forward_headers["proto"] or ""
        if proto.lower() not in {"http", "https"}:
            logger.debug("forward_haders.parse.invalid_proto '%s'", proto)
            raise InvalidForwardHeader

        return cls(
            method=cast(HTTPMethod, method),
            proto=cast(Literal["http", "https"], proto),
            host=forward_headers["host"] or "",
            uri=forward_headers["uri"] or "",
            source=forward_headers["source"] or "",
        )

    @classmethod
    def decode(cls, value: str) -> ForwardHeaders:
        # TODO: Set a different max age from cookie (should be longer per default?)
        loaded = settings.SIGNING.timed.loads(
            value, max_age=settings.LOGIN_COOKIE_MAX_AGE
        )
        return cls.parse(loaded)

    @property
    def url_unparsed(self) -> str:
        return f"{self.proto}://{self.host}{self.uri}"

    def serialize(self) -> dict[str, Any]:
        return {
            "x-forwarded-method": self.method,
            "x-forwarded-proto": self.proto,
            "x-forwarded-host": self.host,
            "x-forwarded-uri": self.uri,
            "x-forwarded-for": self.source,
        }

    def encode(self) -> str:
        encoded = settings.SIGNING.timed.dumps(self.serialize())
        assert isinstance(encoded, str)
        return encoded


class PartialSignature(BaseModel):
    email: EmailStr
    signature: str

    @classmethod
    def url_decode(cls, value: str) -> PartialSignature:
        serializer = settings.SIGNING.timed.serializer
        try:
            loaded = serializer.loads(itsdangerous_base64_decode(value))
            if not isinstance(loaded, abc.Mapping):
                raise TypeError("Encoded value was not a mapping")
        except (BadData, ValueError, TypeError) as exc:
            logger.debug("partial_signature.url_decode.failed", exc_info=True)
            raise ValidationError([ErrorWrapper(exc, ROOT_KEY)], cls) from exc

        return cls.parse_obj(loaded)

    def url_encode(self) -> str:
        serializer = settings.SIGNING.timed.serializer
        return itsdangerous_base64_encode(serializer.dumps(self.serialize())).decode()

    def serialize(self) -> dict[str, Any]:
        return {"email": self.email, "signature": self.signature}


@dataclass(frozen=True)
class LoginSignature:
    email: str
    code: str
    signature: str

    @classmethod
    def create(cls, email: str, valid_code: bool) -> LoginSignature:
        code = f"{secrets.randbelow(1000000):06d}" if valid_code else "invalid"
        signature = settings.SIGNING.timed.dumps({"email": email, "code": code})
        assert isinstance(signature, str)
        return cls(email=email, code=code, signature=signature)

    @classmethod
    def is_valid(cls, email: str, code: str, signature: str) -> bool:
        # Expects signature to not include the initially signed payload
        # Basically a signature that comes out of 'create'
        signer = settings.SIGNING.timed
        payload = signer.dump_payload({"email": email, "code": code}).decode("utf-8")
        full = settings.SIGNING.separator.join([payload, signature])
        try:
            signer.loads(full, max_age=settings.LOGIN_SIGNATURE_MAX_AGE)
            return True
        except BadSignature:
            return False
        except BadData:
            logger.warning("login_signature.is_valid.bad_data", exc_info=True)
            return False

    @property
    def has_valid_code(self) -> bool:
        return self.code != "invalid"

    @property
    def signature_without_payload(self) -> str:
        # Throw away the data from the signature, so as whomever that wants to login
        # has to provide its correct values
        separator = settings.SIGNING.separator
        __, timestamp, signed = self.signature.rsplit(separator, 2)
        return f"{timestamp}{separator}{signed}"

    @property
    def partial(self) -> PartialSignature:
        return PartialSignature(
            email=self.email, signature=self.signature_without_payload
        )
