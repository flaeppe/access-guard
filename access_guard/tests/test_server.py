import random
from functools import partial, singledispatchmethod
from http import HTTPStatus
from http.cookies import SimpleCookie
from typing import Any
from unittest import mock

import pytest
from itsdangerous.encoding import base64_encode
from itsdangerous.exc import BadData, SignatureExpired
from requests.cookies import RequestsCookieJar
from requests.models import Response
from starlette.datastructures import URL
from starlette.testclient import TestClient

from .. import settings
from ..schema import ForwardHeaders, LoginSignature, PartialSignature
from .factories import ForwardHeadersFactory

mock_send_mail = mock.patch("access_guard.server.send_mail", autospec=True)
# TODO: Make a mock.patch.object(?)
mock_time_signer_unsign = mock.patch(
    "itsdangerous.timed.TimestampSigner.unsign", autospec=True
)


def get_cookies(response: Response) -> SimpleCookie:
    return (
        SimpleCookie(set_cookie)
        if (set_cookie := response.headers.get("set-cookie")) is not None
        else SimpleCookie()
    )


def assert_cookie_unset(cookie: str, response: Response, domain: str) -> None:
    cookies = get_cookies(response)
    assert cookie in cookies
    assert cookies[cookie].value == ""
    assert cookies[cookie]["domain"] == domain


assert_login_cookie_unset = partial(assert_cookie_unset, "access-guard-forwarded")
assert_verification_cookie_unset = partial(assert_cookie_unset, "access-guard-session")


def assert_valid_login_cookie(
    response: Response,
    forward_headers: ForwardHeaders,
    domain: str,
) -> None:
    cookies = get_cookies(response)
    assert "access-guard-forwarded" in cookies
    cookie = cookies["access-guard-forwarded"]
    assert settings.SIGNING.timed.loads(cookie.value) == forward_headers.serialize()
    assert cookie["max-age"] == "3600"
    assert cookie["domain"] == domain
    assert not cookie["secure"]
    assert cookie["httponly"]
    assert cookie["path"] == "/"


def encode_for_path(payload: dict[str, Any]) -> str:
    return base64_encode(settings.SIGNING.timed.serializer.dumps(payload)).decode()


class TestAuth:
    @pytest.fixture(autouse=True)
    def _setup(self, api_client: TestClient, auth_url: str) -> None:
        self.api_client = api_client
        self.url = auth_url

    def test_redirects_to_auth_host_when_no_login_cookie(self) -> None:
        forward_headers = ForwardHeadersFactory.create()
        response = self.api_client.get(
            self.url,
            headers=forward_headers.serialize(),
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == f"http://{settings.DOMAIN}/auth"
        assert_valid_login_cookie(response, forward_headers, settings.DOMAIN)

    def test_returns_success_with_valid_verification_cookie(self) -> None:
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name="access-guard-session",
            value=settings.SIGNING.timed.dumps({"email": "verified@email.com"}),
            domain=settings.DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        # Set a login cookie and see that it's removed
        cookie_jar.set(
            name="access-guard-forwarded",
            value="something",
            domain=settings.DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.get(self.url, cookies=cookie_jar)
        assert response.status_code == HTTPStatus.OK
        assert response.text == ""
        assert_login_cookie_unset(response, settings.DOMAIN)

    # TODO: Parameterize missing any combination of headers
    def test_returns_unauthenticated_when_x_forwarded_headers_missing(self) -> None:
        response = self.api_client.get(self.url)
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response.text == ""
        assert_login_cookie_unset(response, settings.DOMAIN)

    def test_renders_login_form_on_get_when_login_cookie_is_valid(
        self, login_cookie_set: RequestsCookieJar
    ) -> None:
        response = self.api_client.get(self.url, cookies=login_cookie_set)
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response.template.name == "send_email.html"
        cookies = get_cookies(response)
        assert "access-guard-forwarded" in cookies
        assert (
            cookies["access-guard-forwarded"]
            == login_cookie_set["access-guard-forwarded"]
        )

    def test_rerenders_send_email_form_on_posting_invalid_email(
        self, login_cookie_set: RequestsCookieJar
    ) -> None:
        with mock_send_mail as send_mail:
            response = self.api_client.post(
                self.url,
                data={"email": "!#@invalid@email.com"},
                cookies=login_cookie_set,
            )

        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.template.name == "send_email.html"
        assert "errors" in response.context
        assert response.context["errors"] == [
            {
                "loc": ("email",),
                "msg": "value is not a valid email address",
                "type": "value_error.email",
            },
        ]
        send_mail.assert_not_called()

    def test_verification_email_is_not_sent_when_email_not_matching_any_pattern(
        self, login_cookie_set: RequestsCookieJar
    ) -> None:
        with mock_send_mail as send_mail:
            response = self.api_client.post(
                self.url,
                data={"email": "someone@else.com"},
                cookies=login_cookie_set,
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.SEE_OTHER
        path_param = LoginSignature.create(
            email="someone@else.com", valid_code=False
        ).partial.url_encode()
        assert (
            response.headers["location"]
            == f"http://{settings.DOMAIN}/verify/{path_param}"
        )
        send_mail.assert_not_called()

    def test_sends_verification_email_when_email_matching_pattern(
        self, login_cookie_set: RequestsCookieJar
    ) -> None:
        mock_randint = mock.patch(
            "access_guard.schema.secrets.randbelow", autospec=True
        )
        login_signature = LoginSignature(
            email="someone@test.com",
            code="001337",
            signature=settings.SIGNING.timed.dumps(
                {"email": "someone@test.com", "code": "001337"}
            ),
        )
        with mock_send_mail as send_mail, mock_randint as randint:
            randint.return_value = 1337
            response = self.api_client.post(
                self.url,
                data={"email": login_signature.email},
                cookies=login_cookie_set,
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.SEE_OTHER
        assert (
            response.headers["location"]
            == f"http://{settings.DOMAIN}/verify/{login_signature.partial.url_encode()}"
        )
        send_mail.assert_called_once_with(login_signature)

    def test_returns_unauthenticated_with_tampered_login_cookie(self) -> None:
        forward_headers = ForwardHeadersFactory.create()
        signature = forward_headers.encode()
        cookies = RequestsCookieJar()
        cookies.set(
            name="access-guard-forwarded",
            value=signature[1:],
            domain=settings.DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.get(
            self.url,
            headers=forward_headers.serialize(),
            cookies=cookies,
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert_login_cookie_unset(response, settings.DOMAIN)

    def test_can_reset_cookie_expired_login_cookie_when_forwarded_headers_exists(
        self,
        expired_login_cookie_set: RequestsCookieJar,
    ) -> None:
        forward_headers = ForwardHeadersFactory.create()
        response = self.api_client.get(
            self.url,
            headers=forward_headers.serialize(),
            cookies=expired_login_cookie_set,
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == f"http://{settings.DOMAIN}/auth"
        assert_valid_login_cookie(response, forward_headers, settings.DOMAIN)

    def test_can_reset_signature_expired_login_cookie_when_forward_headers_exists(
        self, login_cookie_set: RequestsCookieJar
    ) -> None:
        forward_headers = ForwardHeadersFactory.create()
        with mock_time_signer_unsign as unsign:
            unsign.side_effect = SignatureExpired("expired")
            response = self.api_client.get(
                self.url,
                headers=forward_headers.serialize(),
                cookies=login_cookie_set,
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == f"http://{settings.DOMAIN}/auth"
        assert_valid_login_cookie(response, forward_headers, settings.DOMAIN)
        unsign.assert_called_once_with(
            mock.ANY,
            login_cookie_set["access-guard-forwarded"].encode("utf-8"),
            max_age=60 * 60,
            return_timestamp=True,
        )

    def test_unsets_cookie_expired_login_cookie_when_forward_headers_are_missing(
        self, expired_login_cookie_set: RequestsCookieJar
    ) -> None:
        response = self.api_client.get(
            self.url,
            cookies=expired_login_cookie_set,
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert_login_cookie_unset(response, settings.DOMAIN)

    def test_deletes_signature_expired_login_cookie_when_forward_headers_are_missing(
        self, login_cookie_set: RequestsCookieJar
    ) -> None:
        with mock_time_signer_unsign as unsign:
            unsign.side_effect = SignatureExpired("expired")
            response = self.api_client.get(
                self.url,
                cookies=login_cookie_set,
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert_login_cookie_unset(response, settings.DOMAIN)
        unsign.assert_called_once_with(
            mock.ANY,
            login_cookie_set["access-guard-forwarded"].encode("utf-8"),
            max_age=60 * 60,
            return_timestamp=True,
        )

    def test_redirects_to_auth_service_domain_if_not_there_before_form_validation(
        self, login_cookie_set: RequestsCookieJar
    ) -> None:
        with mock.patch.object(
            URL, "netloc", mock.PropertyMock(return_value="somewhere.com")
        ) as request_netloc:
            response = self.api_client.post(
                self.url,
                data={"email": "someone@test.com"},
                cookies=login_cookie_set,
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.TEMPORARY_REDIRECT
        assert "location" in response.headers
        assert response.headers["location"] == f"http://{settings.DOMAIN}/auth"
        request_netloc.assert_called_once()

    def test_deletes_verification_cookie_when_expired(self) -> None:
        request_cookies = RequestsCookieJar()
        session_value = settings.SIGNING.timed.dumps({"email": "verified@email.com"})
        assert isinstance(session_value, str)
        request_cookies.set(
            name="access-guard-session",
            value=session_value,
            domain=settings.DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        forward_headers = ForwardHeadersFactory.create()

        with mock_time_signer_unsign as unsign:
            unsign.side_effect = SignatureExpired("expired")
            response = self.api_client.get(
                self.url,
                cookies=request_cookies,
                headers=forward_headers.serialize(),
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == f"http://{settings.DOMAIN}/auth"
        unsign.assert_called_once_with(
            mock.ANY,
            session_value.encode("utf-8"),
            max_age=60 * 60 * 24,
            return_timestamp=True,
        )
        cookies = get_cookies(response)
        assert set(cookies.keys()) == {
            "access-guard-session",
            "access-guard-forwarded",
        }
        assert cookies["access-guard-session"].value == ""
        assert_valid_login_cookie(response, forward_headers, settings.DOMAIN)

    def test_ignores_tampered_verification_cookie(self) -> None:
        session_value = settings.SIGNING.timed.dumps({"email": "verified@email.com"})
        assert isinstance(session_value, str)
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name="access-guard-session",
            value=session_value[1:],
            domain=settings.DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.get(
            self.url, cookies=cookie_jar, allow_redirects=False
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response.text == ""
        assert_verification_cookie_unset(response, settings.DOMAIN)

    def test_handles_verification_cookie_with_bad_data(self) -> None:
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name="access-guard-session",
            value="baddata",
            domain=settings.DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        with mock_time_signer_unsign as unsign:
            unsign.side_effect = BadData("very bad")
            response = self.api_client.get(
                self.url, data={}, cookies=cookie_jar, allow_redirects=False
            )

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response.text == ""
        assert_verification_cookie_unset(response, settings.DOMAIN)
        unsign.assert_called_once()


class TestVerify:
    @pytest.fixture(autouse=True)
    def _setup(self, api_client: TestClient) -> None:
        self.api_client = api_client

    @singledispatchmethod
    def url(self, obj: object) -> str:
        raise TypeError(  # pragma: no cover
            "Could not resolve url single dispatch method for object of type "
            f"{obj.__qualname__!r}"
        )

    @url.register
    def _url_from_login_signature(self, obj: LoginSignature) -> str:
        return f"/verify/{obj.partial.url_encode()}"

    @url.register
    def _url_from_two_tuple(self, obj: tuple) -> str:
        email, signature = obj
        path_param = PartialSignature(email=email, signature=signature).url_encode()
        return f"/verify/{path_param}"

    @url.register
    def _url_from_string(self, obj: str) -> str:
        return f"/verify/{obj}"

    @pytest.mark.parametrize(
        "method,payload_key",
        (
            pytest.param("POST", "data", id="form"),
            pytest.param("GET", "params", id="query params"),
        ),
    )
    def test_can_verify_via(self, method: str, payload_key: str) -> None:
        headers = ForwardHeadersFactory.create()
        request_cookies = RequestsCookieJar()
        request_cookies.set(
            name="access-guard-forwarded",
            value=headers.encode(),
            domain=settings.DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        login_signature = LoginSignature.create(
            email="someone@email.com", valid_code=True
        )
        data = {"code": login_signature.code}

        response = self.api_client.request(
            method,
            self.url(login_signature),
            cookies=request_cookies,
            allow_redirects=False,
            **{payload_key: data},
        )

        assert response.status_code == HTTPStatus.FOUND
        assert response.headers["location"] == (
            f"{headers.proto}://{headers.host}{headers.uri}"
        )
        cookies = get_cookies(response)
        assert "access-guard-session" in cookies
        assert settings.SIGNING.timed.loads(cookies["access-guard-session"].value) == {
            "email": "someone@email.com"
        }
        assert_login_cookie_unset(response, settings.DOMAIN)

    def test_returns_bad_request_with_invalid_code(
        self, valid_verification: tuple[LoginSignature, RequestsCookieJar]
    ) -> None:
        login_signature, request_cookies = valid_verification
        swap_choices = set(range(9)) - {int(login_signature.code[0])}
        data = {
            "code": str(random.choice(list(swap_choices))) + login_signature.code[1:],
        }
        response = self.api_client.post(
            self.url(login_signature),
            data=data,
            cookies=request_cookies,
            allow_redirects=False,
        )

        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.context["errors"] == [
            {
                "loc": ("__root__",),
                "msg": "code is invalid",
                "type": "value_error.invalid",
            }
        ]

    def test_returns_unauthenticated_with_tampered_login_cookie(self) -> None:
        forward_headers = ForwardHeadersFactory.create()
        signature = forward_headers.encode()
        cookies = RequestsCookieJar()
        cookies.set(
            name="access-guard-forwarded",
            value=signature[1:],
            domain=settings.DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.get(
            self.url(("tampered@email.com", "signed")),
            headers=forward_headers.serialize(),
            cookies=cookies,
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert_login_cookie_unset(response, settings.DOMAIN)

    def test_redirects_to_auth_on_cookie_expired_login_cookie(
        self, expired_login_cookie_set: RequestsCookieJar
    ) -> None:
        response = self.api_client.get(
            self.url(("expired@email.com", "signed")),
            cookies=expired_login_cookie_set,
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == f"http://{settings.DOMAIN}/auth"
        assert_login_cookie_unset(response, settings.DOMAIN)
        assert_verification_cookie_unset(response, settings.DOMAIN)

    def test_redirects_to_auth_on_signature_expired_login_cookie(
        self, login_cookie_set: RequestsCookieJar
    ) -> None:
        with mock_time_signer_unsign as unsign:
            unsign.side_effect = SignatureExpired("expired")
            response = self.api_client.get(
                self.url(("expired@email.com", "signed")),
                cookies=login_cookie_set,
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == f"http://{settings.DOMAIN}/auth"
        assert_login_cookie_unset(response, settings.DOMAIN)
        assert_verification_cookie_unset(response, settings.DOMAIN)
        unsign.assert_called_once_with(
            mock.ANY,
            login_cookie_set["access-guard-forwarded"].encode("utf-8"),
            max_age=60 * 60,
            return_timestamp=True,
        )

    def test_can_not_verify_invalid_generated_signature(
        self, login_cookie_set: RequestsCookieJar
    ) -> None:
        login_signature = LoginSignature.create(
            email="someone@test.com", valid_code=False
        )
        response = self.api_client.post(
            self.url(login_signature),
            data={"code": login_signature.code},
            cookies=login_cookie_set,
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.template.name == "verify.html"
        assert set(response.context.keys()) == {
            "request",
            "partial_signature",
            "errors",
        }
        assert response.context["partial_signature"] == login_signature.partial
        assert response.context["errors"] == [
            {"loc": ("code",), "msg": "code is invalid", "type": "value_error.invalid"},
        ]

    def test_returns_bad_request_on_verify_refresh_page(
        self, valid_verification: tuple[LoginSignature, RequestsCookieJar]
    ) -> None:
        login_signature, cookies = valid_verification
        response = self.api_client.get(self.url(login_signature), cookies=cookies)

        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.template.name == "verify.html"
        # Don't expect errors when no data was sent
        assert set(response.context.keys()) == {"request", "partial_signature"}
        assert response.context["partial_signature"] == login_signature.partial

    def test_returns_success_with_valid_verification_cookie(self) -> None:
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name="access-guard-session",
            value=settings.SIGNING.timed.dumps({"email": "verified@email.com"}),
            domain=settings.DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        # Set a login cookie and see that it's removed
        cookie_jar.set(
            name="access-guard-forwarded",
            value="something",
            domain=settings.DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.post(
            self.url(("success@email.com", "signed")), data={}, cookies=cookie_jar
        )
        assert response.status_code == HTTPStatus.OK
        assert response.text == ""
        assert_login_cookie_unset(response, settings.DOMAIN)

    def test_ignores_tampered_verification_cookie(self) -> None:
        session_value = settings.SIGNING.timed.dumps({"email": "verified@email.com"})
        assert isinstance(session_value, str)
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name="access-guard-session",
            value=session_value[1:],
            domain=settings.DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.post(
            self.url(("tampered@email.com", "signed")),
            data={},
            cookies=cookie_jar,
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == f"http://{settings.DOMAIN}/auth"
        assert response.text == ""
        assert_login_cookie_unset(response, settings.DOMAIN)
        assert_verification_cookie_unset(response, settings.DOMAIN)

    def test_handles_verification_cookie_with_bad_data(self) -> None:
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name="access-guard-session",
            value="baddata",
            domain=settings.DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        with mock_time_signer_unsign as unsign:
            unsign.side_effect = BadData("very bad")
            response = self.api_client.get(
                self.url(("bad@data.com", "signed")),
                cookies=cookie_jar,
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == f"http://{settings.DOMAIN}/auth"
        assert response.text == ""
        assert_login_cookie_unset(response, settings.DOMAIN)
        assert_verification_cookie_unset(response, settings.DOMAIN)
        unsign.assert_called_once()

    @pytest.mark.parametrize(
        "path_param",
        (
            pytest.param(base64_encode("notjson").decode(), id="is not valid json"),
            pytest.param("notbase64encoded", id="is not base64 encoded"),
            pytest.param(encode_for_path(["notdict"]), id="payload is not dict"),
            pytest.param(
                encode_for_path({"email": "valid@email.com"}), id="payload missing key"
            ),
            pytest.param(
                encode_for_path({"email": "invalidemail", "signature": "something"}),
                id="payload email is not a valid email",
            ),
            pytest.param(
                encode_for_path(
                    {"email": "valid@email.com", "signature": ["I'm in a list"]}
                ),
                id="payload signature is not string",
            ),
        ),
    )
    def test_returns_not_found_when_path_param(self, path_param: str) -> None:
        response = self.api_client.get(self.url(path_param), allow_redirects=False)
        assert response.status_code == HTTPStatus.NOT_FOUND
        assert response.text == ""

    def test_body_data_cannot_override_data_from_path_payload(
        self, valid_verification: tuple[LoginSignature, RequestsCookieJar]
    ) -> None:
        login_signature, cookies = valid_verification
        response = self.api_client.post(
            self.url(("invalid@email.com", login_signature.signature_without_payload)),
            data={"code": login_signature.code, "email": login_signature.email},
            cookies=cookies,
            allow_redirects=False,
        )

        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert set(response.context.keys()) == {
            "request",
            "partial_signature",
            "errors",
        }
        assert response.context["errors"] == [
            {
                "loc": ("__root__",),
                "msg": "code is invalid",
                "type": "value_error.invalid",
            }
        ]

    def test_data_from_path_payload_cannot_override_body_data(
        self, valid_verification: tuple[LoginSignature, RequestsCookieJar]
    ) -> None:
        login_signature, cookies = valid_verification
        data = {"code": "invalid"}
        response = self.api_client.post(
            self.url(
                encode_for_path(
                    {
                        "email": login_signature.email,
                        "signature": login_signature.signature_without_payload,
                        "code": login_signature.code,
                    }
                )
            ),
            data=data,
            cookies=cookies,
            allow_redirects=False,
        )

        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert set(response.context.keys()) == {
            "request",
            "partial_signature",
            "errors",
        }
        assert response.context["errors"] == [
            {"loc": ("code",), "msg": "code is invalid", "type": "value_error.invalid"}
        ]
