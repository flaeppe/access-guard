from functools import partial, singledispatchmethod
from http import HTTPStatus
from http.cookies import SimpleCookie
from unittest import mock
from urllib.parse import urljoin

import pytest
from itsdangerous.encoding import base64_encode
from itsdangerous.exc import BadData, SignatureExpired
from requests.cookies import RequestsCookieJar
from requests.models import Response
from starlette.testclient import TestClient

from .. import csrf, settings
from ..schema import AuthSignature, ForwardHeaders
from .factories import ForwardHeadersFactory

mock_send_mail = mock.patch("access_guard.routes.send.send_mail", autospec=True)
mock_time_signer_loads = mock.patch.object(
    settings.SIGNING.timed, "loads", autospec=True
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


assert_auth_cookie_unset = partial(assert_cookie_unset, settings.AUTH_COOKIE_NAME)
assert_verification_cookie_unset = partial(
    assert_cookie_unset, settings.VERIFIED_COOKIE_NAME
)
assert_csrf_cookie_unset = partial(assert_cookie_unset, csrf.CSRF_COOKIE_NAME)


def assert_valid_auth_cookie(
    response: Response,
    forward_headers: ForwardHeaders,
    domain: str,
) -> None:
    cookies = get_cookies(response)
    assert settings.AUTH_COOKIE_NAME in cookies
    cookie = cookies[settings.AUTH_COOKIE_NAME]
    assert settings.SIGNING.timed.loads(cookie.value) == forward_headers.serialize()
    assert cookie["max-age"] == "3600"
    assert cookie["domain"] == domain
    assert not cookie["secure"]
    assert cookie["httponly"]
    assert cookie["path"] == "/"


def assert_valid_csrf_cookie(response: Response, domain: str) -> None:
    cookies = get_cookies(response)
    assert csrf.CSRF_COOKIE_NAME in cookies
    cookie = cookies[csrf.CSRF_COOKIE_NAME]
    assert "csrf_token" in response.context
    body_token = response.context["csrf_token"]
    settings.SIGNING.url_safe.loads(
        settings.SIGNING.separator.join(
            [settings.SIGNING.url_safe.dump_payload(body_token).decode(), cookie.value]
        )
    )


class TestAuth:
    @pytest.fixture(autouse=True)
    def _setup(self, api_client: TestClient, auth_url: str) -> None:
        self.api_client = api_client
        self.url = auth_url

    def test_redirects_to_send_when_no_auth_cookie(self) -> None:
        # We set proto to see that redirect is attempted with its value
        forward_headers = ForwardHeadersFactory.create(proto="https")
        response = self.api_client.get(
            self.url,
            headers=forward_headers.serialize(),
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.SEE_OTHER
        assert (
            response.headers["location"] == f"https://{settings.AUTH_HOST.netloc}/send"
        )
        assert_valid_auth_cookie(response, forward_headers, settings.COOKIE_DOMAIN)

    def test_returns_success_with_valid_verification_cookie(self) -> None:
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name=settings.VERIFIED_COOKIE_NAME,
            value=settings.SIGNING.timed.dumps({"email": "verified@test.com"}),
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        # Set a auth cookie and see that it's removed
        cookie_jar.set(
            name=settings.AUTH_COOKIE_NAME,
            value="something",
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.get(self.url, cookies=cookie_jar)
        assert response.status_code == HTTPStatus.OK
        assert response.text == ""
        assert_auth_cookie_unset(response, settings.COOKIE_DOMAIN)

    def test_returns_unauthorized_when_x_forwarded_headers_missing(self) -> None:
        response = self.api_client.get(self.url)
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response.text == ""

    def test_ignores_tampered_verification_cookie(self) -> None:
        session_value = settings.SIGNING.timed.dumps({"email": "verified@email.com"})
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name=settings.VERIFIED_COOKIE_NAME,
            value=session_value[1:],
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.get(
            self.url, cookies=cookie_jar, allow_redirects=False
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response.text == ""
        assert_verification_cookie_unset(response, settings.COOKIE_DOMAIN)

    def test_starts_email_verification_when_verified_expired_and_forward_headers_exists(
        self,
    ) -> None:
        session_value = settings.SIGNING.timed.dumps({"email": "verified@email.com"})
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name=settings.VERIFIED_COOKIE_NAME,
            value=session_value,
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        forward_headers = ForwardHeadersFactory.create()
        with mock_time_signer_loads as loads:
            loads.side_effect = SignatureExpired("expired")
            response = self.api_client.get(
                self.url,
                cookies=cookie_jar,
                headers=forward_headers.serialize(),
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == urljoin(str(settings.AUTH_HOST), "/send")
        assert_valid_auth_cookie(response, forward_headers, settings.COOKIE_DOMAIN)
        assert_verification_cookie_unset(response, settings.COOKIE_DOMAIN)
        loads.assert_called_once_with(
            session_value, max_age=settings.VERIFY_SIGNATURE_MAX_AGE
        )

    def test_verified_with_disallowed_email_missing_forward_headers_is_unauthorized(
        self,
    ) -> None:
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name=settings.VERIFIED_COOKIE_NAME,
            value=settings.SIGNING.timed.dumps({"email": "non-matching@email.com"}),
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )

        response = self.api_client.get(
            self.url, cookies=cookie_jar, allow_redirects=False
        )

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert_verification_cookie_unset(response, settings.COOKIE_DOMAIN)

    def test_verified_with_disallowed_email_and_forward_headers_redirects_to_send(
        self,
    ) -> None:
        forward_headers = ForwardHeadersFactory.create()
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name=settings.VERIFIED_COOKIE_NAME,
            value=settings.SIGNING.timed.dumps({"email": "non-matching@email.com"}),
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )

        response = self.api_client.get(
            self.url,
            cookies=cookie_jar,
            headers=forward_headers.serialize(),
            allow_redirects=False,
        )

        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == urljoin(str(settings.AUTH_HOST), "/send")
        assert_valid_auth_cookie(response, forward_headers, settings.COOKIE_DOMAIN)
        assert_verification_cookie_unset(response, settings.COOKIE_DOMAIN)

    def test_returns_unauthorized_with_verification_cookie_with_bad_data(self) -> None:
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name=settings.VERIFIED_COOKIE_NAME,
            value="baddata",
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        with mock_time_signer_loads as loads:
            loads.side_effect = BadData("very bad")
            response = self.api_client.get(
                self.url, data={}, cookies=cookie_jar, allow_redirects=False
            )

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response.text == ""
        assert_verification_cookie_unset(response, settings.COOKIE_DOMAIN)
        loads.assert_called_once_with(
            "baddata", max_age=settings.VERIFY_SIGNATURE_MAX_AGE
        )

    def test_returns_unauthorized_on_invalid_auth_cookie_payload(self) -> None:
        cookies = RequestsCookieJar()
        cookies.set(
            name=settings.AUTH_COOKIE_NAME,
            value=settings.SIGNING.timed.dumps({"unknown": "payload"}),
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.get(self.url, cookies=cookies)

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert_auth_cookie_unset(response, settings.COOKIE_DOMAIN)

    def test_returns_unauthorized_with_tampered_auth_cookie(self) -> None:
        cookies = RequestsCookieJar()
        cookies.set(
            name=settings.AUTH_COOKIE_NAME,
            value=ForwardHeadersFactory.create().encode()[1:],
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.get(self.url, cookies=cookies, allow_redirects=False)
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert_auth_cookie_unset(response, settings.COOKIE_DOMAIN)

    def test_can_recreate_expired_auth_cookie_when_forward_headers_exists(
        self, expired_auth_cookie_set: RequestsCookieJar
    ) -> None:
        forward_headers = ForwardHeadersFactory.create()
        response = self.api_client.get(
            self.url,
            headers=forward_headers.serialize(),
            cookies=expired_auth_cookie_set,
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == urljoin(str(settings.AUTH_HOST), "/send")
        assert_valid_auth_cookie(response, forward_headers, settings.COOKIE_DOMAIN)

    def test_can_recreate_signature_expired_auth_cookie_when_forward_headers_exists(
        self, auth_cookie_set: RequestsCookieJar
    ) -> None:
        forward_headers = ForwardHeadersFactory.create()
        with mock_time_signer_loads as loads:
            loads.side_effect = SignatureExpired("expired")
            response = self.api_client.get(
                self.url,
                headers=forward_headers.serialize(),
                cookies=auth_cookie_set,
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == urljoin(str(settings.AUTH_HOST), "/send")
        assert_valid_auth_cookie(response, forward_headers, settings.COOKIE_DOMAIN)
        loads.assert_called_once_with(
            auth_cookie_set[settings.AUTH_COOKIE_NAME], max_age=60 * 60
        )

    def test_is_unauthorized_with_expired_auth_cookie_and_no_forward_headers(
        self, expired_auth_cookie_set: RequestsCookieJar
    ) -> None:
        response = self.api_client.get(
            self.url,
            cookies=expired_auth_cookie_set,
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED

    def test_is_unauthorized_with_signature_expired_auth_cookie_and_no_forward_headers(
        self, auth_cookie_set: RequestsCookieJar
    ) -> None:
        with mock_time_signer_loads as loads:
            loads.side_effect = SignatureExpired("expired")
            response = self.api_client.get(
                self.url,
                cookies=auth_cookie_set,
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        loads.assert_called_once_with(
            auth_cookie_set[settings.AUTH_COOKIE_NAME],
            max_age=settings.AUTH_COOKIE_MAX_AGE,
        )


class TestSend:
    @pytest.fixture(autouse=True)
    def _setup(self, api_client: TestClient, send_url: str) -> None:
        self.api_client = api_client
        self.url = send_url

    def test_renders_send_email_form_on_get_when_auth_cookie_is_valid(
        self, auth_cookie_set: RequestsCookieJar
    ) -> None:
        response = self.api_client.get(self.url, cookies=auth_cookie_set)
        assert response.status_code == HTTPStatus.OK
        assert response.template.name == "send_email.html"
        assert set(response.context.keys()) == {"request", "host_name", "csrf_token"}
        assert "host_name" in response.context
        assert response.context["host_name"] == "testservice.local"
        assert_valid_csrf_cookie(response, settings.COOKIE_DOMAIN)

    @pytest.mark.parametrize(
        "email",
        (
            pytest.param("sOmeOne@TeSt.CoM", id="mixed case"),
            pytest.param("someone@test.com", id="all lowercase"),
            pytest.param("SOMEONE@TEST.COM", id="all uppercase"),
        ),
    )
    def test_sends_verification_email_when_matching_pattern_as(
        self,
        email: str,
        auth_cookie_set: RequestsCookieJar,
        csrf_token: tuple[str, RequestsCookieJar],
    ) -> None:
        csrf_token, cookies = csrf_token
        with mock_send_mail as send_mail:
            response = self.api_client.post(
                self.url,
                data={"email": email, "csrf_token": csrf_token},
                cookies=cookies,
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.OK
        assert response.template.name == "email_sent.html"
        send_mail.assert_called_once_with(
            email=email.lower(), link=mock.ANY, host_name="testservice.local"
        )
        assert str(send_mail.call_args.kwargs["link"]).startswith(
            urljoin(str(settings.AUTH_HOST), "/verify/")
        )
        assert_auth_cookie_unset(response, settings.COOKIE_DOMAIN)
        assert_csrf_cookie_unset(response, settings.COOKIE_DOMAIN)

    def test_verification_email_is_not_sent_when_email_not_matching_any_pattern(
        self,
        auth_cookie_set: RequestsCookieJar,
        csrf_token: tuple[str, RequestsCookieJar],
    ) -> None:
        csrf_token, cookies = csrf_token
        with mock_send_mail as send_mail:
            response = self.api_client.post(
                self.url,
                data={"email": "someone@else.com", "csrf_token": csrf_token},
                cookies=cookies,
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.OK
        assert response.template.name == "email_sent.html"
        send_mail.assert_not_called()
        assert_auth_cookie_unset(response, settings.COOKIE_DOMAIN)
        assert_csrf_cookie_unset(response, settings.COOKIE_DOMAIN)

    @pytest.mark.parametrize(
        "email,msg,error_code",
        (
            pytest.param(
                "!#@invalid@email.com",
                "value is not a valid email address",
                "value_error.email",
                id="invalid email",
            ),
            pytest.param(
                None, "field required", "value_error.missing", id="email as none"
            ),
            pytest.param(
                ["i'm a list"],
                "value is not a valid email address",
                "value_error.email",
                id="email as invalid type",
            ),
        ),
    )
    def test_rerenders_send_email_form_on_posting(
        self,
        email: str,
        msg: str,
        error_code: str,
        auth_cookie_set: RequestsCookieJar,
        csrf_token: tuple[str, RequestsCookieJar],
    ) -> None:
        csrf_token, cookies = csrf_token
        with mock_send_mail as send_mail:
            response = self.api_client.post(
                self.url,
                data={"email": email, "csrf_token": csrf_token},
                cookies=cookies,
            )

        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.template.name == "send_email.html"
        assert set(response.context.keys()) == {
            "request",
            "host_name",
            "csrf_token",
            "errors",
        }
        assert response.context["errors"] == [
            {"loc": ("email",), "msg": msg, "type": error_code}
        ]
        assert response.context["host_name"] == "testservice.local"
        send_mail.assert_not_called()
        # Should not do anything with auth cookie
        assert settings.AUTH_COOKIE_NAME not in get_cookies(response)

    def test_returns_unauthorized_on_tampered_auth_cookie(self) -> None:
        cookies = RequestsCookieJar()
        cookies.set(
            name=settings.AUTH_COOKIE_NAME,
            value=ForwardHeadersFactory.create().encode()[1:],
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.get(self.url, cookies=cookies, allow_redirects=False)
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert_auth_cookie_unset(response, settings.COOKIE_DOMAIN)

    def test_returns_unauthorized_on_expired_auth_cookie(
        self, expired_auth_cookie_set: RequestsCookieJar
    ) -> None:
        response = self.api_client.get(
            self.url, cookies=expired_auth_cookie_set, allow_redirects=False
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED

    def test_returns_bad_request_when_csrf_token_is_missing(
        self,
        auth_cookie_set: RequestsCookieJar,
        csrf_token: tuple[str, RequestsCookieJar],
    ) -> None:
        __, cookies = csrf_token
        response = self.api_client.post(
            self.url, data={"email": "someone@email.com"}, cookies=cookies
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.template.name == "send_email.html"
        assert set(response.context.keys()) == {
            "request",
            "host_name",
            "csrf_token",
            "errors",
        }
        assert response.context["errors"] == [
            {
                "loc": ("csrf_token",),
                "msg": "field required",
                "type": "value_error.missing",
            }
        ]

    def test_returns_forbidden_when_csrf_cookie_is_missing(
        self, auth_cookie_set: RequestsCookieJar
    ) -> None:
        csrf_raw, __ = csrf.get_token()
        response = self.api_client.post(
            self.url,
            data={"email": "someone@email.com", "csrf_token": csrf_raw},
            cookies=auth_cookie_set,
        )
        assert response.status_code == HTTPStatus.FORBIDDEN

    def test_returns_forbidden_when_csrf_cookie_is_tampered_with(
        self, auth_cookie_set: RequestsCookieJar
    ) -> None:
        csrf_raw, csrf_signed = csrf.get_token()
        auth_cookie_set.set(
            name=csrf.CSRF_COOKIE_NAME,
            value=csrf_signed[1:],
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.post(
            self.url,
            data={"email": "someone@email.com", "csrf_token": csrf_raw},
            cookies=auth_cookie_set,
        )
        assert response.status_code == HTTPStatus.FORBIDDEN

    def test_returns_forbidden_when_csrf_token_does_not_match_csrf_cookie(
        self,
        auth_cookie_set: RequestsCookieJar,
        csrf_token: tuple[str, RequestsCookieJar],
    ) -> None:
        csrf_raw, cookies = csrf_token
        response = self.api_client.post(
            self.url,
            data={"email": "someone@email.com", "csrf_token": csrf_raw[1:]},
            cookies=cookies,
        )
        assert response.status_code == HTTPStatus.FORBIDDEN


class TestVerify:
    @pytest.fixture(autouse=True)
    def _setup(self, api_client: TestClient) -> None:
        self.api_client = api_client

    @singledispatchmethod
    def url(self, obj: object) -> str:
        raise TypeError(  # pragma: no cover
            "Could not resolve url single dispatch method for object of type "
            f"{type(obj).__qualname__!r}"
        )

    @url.register
    def _url_from_auth_signature(self, obj: AuthSignature) -> str:
        return f"/verify/{obj.signature}"

    @url.register
    def _url_from_string(self, obj: str) -> str:
        return f"/verify/{obj}"

    def test_can_verify(self) -> None:
        headers = ForwardHeadersFactory.create()
        auth_signature = AuthSignature.create(
            email="someone@test.com", forward_headers=headers
        )

        response = self.api_client.get(self.url(auth_signature), allow_redirects=False)

        assert response.status_code == HTTPStatus.FOUND
        assert response.headers["location"] == (
            f"{headers.proto}://{headers.host}{headers.uri}"
        )
        cookies = get_cookies(response)
        assert settings.VERIFIED_COOKIE_NAME in cookies
        assert settings.SIGNING.timed.loads(
            cookies[settings.VERIFIED_COOKIE_NAME].value
        ) == {"email": "someone@test.com"}

    def test_returns_not_found_when_signature_validation_returns_none(
        self, valid_auth_signature: AuthSignature
    ) -> None:
        with mock.patch.object(AuthSignature, "loads", autospec=True) as validate:
            validate.return_value = None
            response = self.api_client.get(
                self.url(valid_auth_signature),
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.NOT_FOUND
        validate.assert_called_once_with(valid_auth_signature.signature)

    def test_redirects_to_auth_on_expired_auth_signature(
        self, valid_auth_signature: AuthSignature
    ) -> None:
        with mock_time_signer_loads as loads:
            loads.side_effect = SignatureExpired("expired")
            response = self.api_client.get(
                self.url(valid_auth_signature), allow_redirects=False
            )

        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == urljoin(str(settings.AUTH_HOST), "/auth")

    @pytest.mark.parametrize(
        "path_param",
        (
            pytest.param(base64_encode("notjson").decode(), id="is not valid json"),
            pytest.param("notbase64encoded", id="is not base64 encoded"),
            pytest.param(
                settings.SIGNING.timed.dumps(["notdict"]), id="payload is not dict"
            ),
            pytest.param(settings.SIGNING.timed.dumps({}), id="payload missing key"),
            pytest.param(
                settings.SIGNING.timed.dumps({"email": "invalidemail"}),
                id="payload email is not a valid email",
            ),
        ),
    )
    def test_returns_not_found_when_signature(
        self, path_param: str, auth_cookie_set: RequestsCookieJar
    ) -> None:
        response = self.api_client.get(
            self.url(path_param), cookies=auth_cookie_set, allow_redirects=False
        )
        assert response.status_code == HTTPStatus.NOT_FOUND
        assert response.text == ""
