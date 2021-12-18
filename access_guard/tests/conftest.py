from typing import AsyncGenerator

import pytest
from requests.cookies import RequestsCookieJar
from starlette.datastructures import URL
from starlette.testclient import TestClient

# Set test environment. Important that we touch this before any other application
# modules, due to globals etc.
from ..environ import environ  # noqa

environ.load(  # noqa
    {
        "email_patterns": (".*@example.com",),
        "secret": "supersecret",
        "auth_host": URL("http://auth.example.com/"),
        "trusted_hosts": ("auth.example.com",),
        "cookie_domain": "example.com",
        "cookie_secure": False,
        "auth_cookie_name": "auth-test",
        "verified_cookie_name": "verified-test",
        "email_host": "email-host",
        "email_port": "666",
        "from_email": "access-guard@example.com",
        "email_subject": "Test verification",
    }
)

from .. import settings  # noqa: E402
from ..schema import AuthSignature  # noqa: E402
from .factories import ForwardHeadersFactory  # noqa: E402


@pytest.fixture(scope="function")
async def api_client() -> AsyncGenerator[TestClient, None]:
    from .. import server

    with TestClient(
        server.app, base_url=f"http://{settings.AUTH_HOST.netloc}"
    ) as client:
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


@pytest.fixture(scope="session")
def auth_url() -> str:
    return "/auth"


@pytest.fixture(scope="session")
def send_url() -> str:
    return "/send"


@pytest.fixture(scope="function")
def valid_auth_signature() -> AuthSignature:
    return AuthSignature.create(
        email="someone@example.com", forward_headers=ForwardHeadersFactory.create()
    )
