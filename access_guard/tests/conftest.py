from typing import AsyncGenerator
from unittest import mock

import pytest
from requests.cookies import RequestsCookieJar
from starlette.testclient import TestClient

# Set test environment. Important that we touch this before any other application
# modules, due to globals etc.
from ..environ import environ  # noqa

environ.load(  # noqa
    {
        "email_patterns": (".*@test.com",),
        "secret": "supersecret",
        "auth_host": "auth.testserver.local",
        "trusted_hosts": ("auth.testserver.local",),
        "cookie_domain": "testserver.local",
        "cookie_secure": False,
        "auth_cookie_name": "auth-test",
        "verified_cookie_name": "verified-test",
        "email_host": "email-host",
        "email_port": "666",
        "from_email": "access-guard@local.com",
        "email_subject": "Test verification",
    }
)

from .. import server, settings  # noqa: E402
from ..schema import AuthSignature  # noqa: E402
from .factories import ForwardHeadersFactory  # noqa: E402


@pytest.fixture(scope="function")
async def api_client() -> AsyncGenerator[TestClient, None]:
    with mock.patch("uvicorn.run", autospec=True):
        server.run()
        with TestClient(server.app, base_url=f"http://{settings.DOMAIN}") as client:
            yield client


@pytest.fixture(scope="function")
def cookie_jar() -> RequestsCookieJar:
    return RequestsCookieJar()


@pytest.fixture(scope="function")
def auth_cookie_set(cookie_jar: RequestsCookieJar) -> RequestsCookieJar:
    cookie_jar.set(
        name=settings.AUTH_COOKIE_NAME,
        value=ForwardHeadersFactory.create().encode(),
        domain=settings.COOKIE_DOMAIN,
        secure=False,
        rest={"HttpOnly": True},
    )
    return cookie_jar


@pytest.fixture(scope="function")
def expired_auth_cookie_set(cookie_jar: RequestsCookieJar) -> RequestsCookieJar:
    cookie_jar.set(
        name=settings.AUTH_COOKIE_NAME,
        value=ForwardHeadersFactory.create().encode(),
        domain=settings.COOKIE_DOMAIN,
        expires=-1,
        secure=False,
        rest={"HttpOnly": True},
    )
    return cookie_jar


@pytest.fixture(scope="function")
def csrf_token(cookie_jar: RequestsCookieJar) -> tuple[str, RequestsCookieJar]:
    from access_guard import csrf

    raw, signed = csrf.get_token()
    cookie_jar.set(
        name=csrf.CSRF_COOKIE_NAME,
        value=signed,
        domain=settings.COOKIE_DOMAIN,
        secure=False,
        rest={"HttpOnly": True},
    )
    return raw, cookie_jar


@pytest.fixture(scope="session")
def auth_url() -> str:
    return "/auth"


@pytest.fixture(scope="session")
def send_url() -> str:
    return "/send"


@pytest.fixture(scope="function")
def valid_auth_signature() -> AuthSignature:
    return AuthSignature.create(
        email="someone@test.com", forward_headers=ForwardHeadersFactory.create()
    )
