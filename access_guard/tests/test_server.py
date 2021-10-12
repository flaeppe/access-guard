from functools import partial, singledispatchmethod
from http import HTTPStatus
from http.cookies import SimpleCookie
from unittest import mock

import pytest
from itsdangerous.encoding import base64_encode
from itsdangerous.exc import BadData, SignatureExpired
from requests.cookies import RequestsCookieJar
from requests.models import Response
from starlette.datastructures import URL
from starlette.testclient import TestClient

from .. import settings
from ..schema import AuthSignature, ForwardHeaders
from .factories import ForwardHeadersFactory

mock_send_mail = mock.patch("access_guard.server.send_mail", autospec=True)
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


class TestAuth:
    @pytest.fixture(autouse=True)
    def _setup(self, api_client: TestClient, auth_url: str) -> None:
        self.api_client = api_client
        self.url = auth_url

    def test_redirects_to_auth_host_when_no_auth_cookie(self) -> None:
        # We set proto to see that redirect is attempted with its value
        forward_headers = ForwardHeadersFactory.create(proto="https")
        response = self.api_client.get(
            self.url,
            headers=forward_headers.serialize(),
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == f"https://{settings.DOMAIN}/auth"
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

    def test_returns_unauthenticated_when_x_forwarded_headers_missing(self) -> None:
        response = self.api_client.get(self.url)
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response.text == ""
        assert_auth_cookie_unset(response, settings.COOKIE_DOMAIN)

    def test_renders_auth_form_on_get_when_auth_cookie_is_valid(
        self, auth_cookie_set: RequestsCookieJar
    ) -> None:
        response = self.api_client.get(self.url, cookies=auth_cookie_set)
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response.template.name == "send_email.html"
        assert set(response.context.keys()) == {"request", "host_name"}
        assert "host_name" in response.context
        assert response.context["host_name"] == "testservice.local"
        assert "set-cookie" not in response.headers

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
        self, email: str, msg: str, error_code: str, auth_cookie_set: RequestsCookieJar
    ) -> None:
        with mock_send_mail as send_mail:
            response = self.api_client.post(
                self.url, data={"email": email}, cookies=auth_cookie_set
            )

        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.template.name == "send_email.html"
        assert set(response.context.keys()) == {"request", "host_name", "errors"}
        assert response.context["errors"] == [
            {"loc": ("email",), "msg": msg, "type": error_code}
        ]
        assert response.context["host_name"] == "testservice.local"
        send_mail.assert_not_called()
        # Should not do anything with auth cookie
        assert settings.AUTH_COOKIE_NAME not in get_cookies(response)

    def test_verification_email_is_not_sent_when_email_not_matching_any_pattern(
        self, auth_cookie_set: RequestsCookieJar
    ) -> None:
        with mock_send_mail as send_mail:
            response = self.api_client.post(
                self.url,
                data={"email": "someone@else.com"},
                cookies=auth_cookie_set,
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.OK
        assert response.template.name == "email_sent.html"
        send_mail.assert_not_called()
        assert_auth_cookie_unset(response, settings.COOKIE_DOMAIN)

    def test_sends_verification_email_when_email_matching_pattern(
        self, auth_cookie_set: RequestsCookieJar
    ) -> None:
        with mock_send_mail as send_mail:
            response = self.api_client.post(
                self.url,
                data={"email": "someone@test.com"},
                cookies=auth_cookie_set,
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.OK
        assert response.template.name == "email_sent.html"
        send_mail.assert_called_once_with(
            email="someone@test.com", link=mock.ANY, host_name="testservice.local"
        )
        send_mail.call_args.kwargs["link"].startswith(
            f"http://{settings.DOMAIN}/verify/"
        )
        assert_auth_cookie_unset(response, settings.COOKIE_DOMAIN)

    def test_returns_unauthenticated_with_tampered_auth_cookie(self) -> None:
        forward_headers = ForwardHeadersFactory.create()
        signature = forward_headers.encode()
        cookies = RequestsCookieJar()
        cookies.set(
            name=settings.AUTH_COOKIE_NAME,
            value=signature[1:],
            domain=settings.COOKIE_DOMAIN,
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
        assert_auth_cookie_unset(response, settings.COOKIE_DOMAIN)

    def test_can_reset_cookie_expired_auth_cookie_when_forwarded_headers_exists(
        self,
        expired_auth_cookie_set: RequestsCookieJar,
    ) -> None:
        forward_headers = ForwardHeadersFactory.create()
        response = self.api_client.get(
            self.url,
            headers=forward_headers.serialize(),
            cookies=expired_auth_cookie_set,
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == f"http://{settings.DOMAIN}/auth"
        assert_valid_auth_cookie(response, forward_headers, settings.COOKIE_DOMAIN)

    def test_can_reset_signature_expired_auth_cookie_when_forward_headers_exists(
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
        assert response.headers["location"] == f"http://{settings.DOMAIN}/auth"
        assert_valid_auth_cookie(response, forward_headers, settings.COOKIE_DOMAIN)
        loads.assert_called_once_with(
            auth_cookie_set[settings.AUTH_COOKIE_NAME], max_age=60 * 60
        )

    def test_unsets_cookie_expired_auth_cookie_when_forward_headers_are_missing(
        self, expired_auth_cookie_set: RequestsCookieJar
    ) -> None:
        response = self.api_client.get(
            self.url,
            cookies=expired_auth_cookie_set,
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert_auth_cookie_unset(response, settings.COOKIE_DOMAIN)

    def test_deletes_signature_expired_auth_cookie_when_forward_headers_are_missing(
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
        assert_auth_cookie_unset(response, settings.COOKIE_DOMAIN)
        loads.assert_called_once_with(
            auth_cookie_set[settings.AUTH_COOKIE_NAME],
            max_age=settings.AUTH_COOKIE_MAX_AGE,
        )

    def test_redirects_to_auth_service_domain_if_not_there_before_form_validation(
        self,
    ) -> None:
        # We set proto to see that redirect is attempted with its value
        forward_headers = ForwardHeadersFactory.create(proto="https")
        cookies = RequestsCookieJar()
        cookies.set(
            name=settings.AUTH_COOKIE_NAME,
            value=forward_headers.encode(),
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        with mock.patch.object(
            URL, "netloc", mock.PropertyMock(return_value="somewhere.com")
        ) as request_netloc:
            response = self.api_client.post(
                self.url,
                data={"email": "someone@test.com"},
                cookies=cookies,
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.TEMPORARY_REDIRECT
        assert "location" in response.headers
        assert response.headers["location"] == f"https://{settings.DOMAIN}/auth"
        request_netloc.assert_called_once()

    def test_deletes_verification_cookie_when_expired(self) -> None:
        request_cookies = RequestsCookieJar()
        session_value = settings.SIGNING.timed.dumps({"email": "verified@email.com"})
        assert isinstance(session_value, str)
        request_cookies.set(
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
                cookies=request_cookies,
                headers=forward_headers.serialize(),
                allow_redirects=False,
            )

        assert response.status_code == HTTPStatus.SEE_OTHER
        assert response.headers["location"] == f"http://{settings.DOMAIN}/auth"
        loads.assert_called_once_with(
            session_value, max_age=settings.VERIFY_SIGNATURE_MAX_AGE
        )
        assert_verification_cookie_unset(response, settings.COOKIE_DOMAIN)
        assert_valid_auth_cookie(response, forward_headers, settings.COOKIE_DOMAIN)

    def test_ignores_tampered_verification_cookie(self) -> None:
        session_value = settings.SIGNING.timed.dumps({"email": "verified@email.com"})
        assert isinstance(session_value, str)
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

    def test_handles_verification_cookie_with_bad_data(self) -> None:
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

    def test_verified_with_disallowed_email_missing_forward_headers_is_unauthorized(
        self,
    ):
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
        assert_auth_cookie_unset(response, settings.COOKIE_DOMAIN)


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
        assert response.headers["location"] == f"http://{settings.DOMAIN}/auth"

    def test_returns_success_with_valid_verification_cookie(self) -> None:
        forward_headers = ForwardHeadersFactory.create()
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name=settings.VERIFIED_COOKIE_NAME,
            value=settings.SIGNING.timed.dumps(
                {
                    "email": "verified@test.com",
                    "forward_headers": forward_headers.serialize(),
                }
            ),
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.get(self.url("notasignature"), cookies=cookie_jar)
        assert response.status_code == HTTPStatus.OK
        assert response.text == ""

    def test_returns_not_found_with_tampered_verification_cookie(self) -> None:
        session_value = settings.SIGNING.timed.dumps({"email": "verified@email.com"})
        assert isinstance(session_value, str)
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name=settings.VERIFIED_COOKIE_NAME,
            value=session_value[1:],
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.get(
            self.url(session_value),
            cookies=cookie_jar,
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_verification_cookie_with_bad_data_and_invalid_url_results_in_not_found(
        self,
    ) -> None:
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name=settings.VERIFIED_COOKIE_NAME,
            value="baddata",
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.get(
            self.url("doesnotmatter"),
            cookies=cookie_jar,
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.NOT_FOUND

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

    def test_verified_with_disallowed_email_on_invalid_url_returns_not_found(self):
        cookie_jar = RequestsCookieJar()
        cookie_jar.set(
            name=settings.VERIFIED_COOKIE_NAME,
            value=settings.SIGNING.timed.dumps({"email": "non-matching@email.com"}),
            domain=settings.COOKIE_DOMAIN,
            secure=False,
            rest={"HttpOnly": True},
        )
        response = self.api_client.get(
            self.url("signature"),
            cookies=cookie_jar,
            allow_redirects=False,
        )
        assert response.status_code == HTTPStatus.NOT_FOUND
