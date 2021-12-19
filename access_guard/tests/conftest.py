from typing import AsyncGenerator, Generator
from unittest import mock

import aiosmtplib
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


@pytest.fixture()
def mock_smtp_connection() -> Generator[mock.AsyncMock, None, None]:
    connection_mock = mock.AsyncMock(
        spec_set=aiosmtplib.SMTP, name="mocked_smtp_connection"
    )
    with mock.patch.object(
        aiosmtplib.SMTP, "__aenter__", autospec=True, name="mocked_smtp_context"
    ) as context:
        context.return_value = connection_mock
        yield connection_mock


@pytest.fixture()
async def api_client(
    mock_smtp_connection: mock.AsyncMock,
) -> AsyncGenerator[TestClient, None]:
    from .. import server

    with TestClient(
        server.app, base_url=f"http://{settings.AUTH_HOST.netloc}"
    ) as client:
        yield client


@pytest.fixture()
def cookie_jar() -> RequestsCookieJar:
    return RequestsCookieJar()


@pytest.fixture()
def auth_cookie_set(cookie_jar: RequestsCookieJar) -> RequestsCookieJar:
    cookie_jar.set(
        name=settings.AUTH_COOKIE_NAME,
        value=ForwardHeadersFactory.create().encode(),
        domain=settings.COOKIE_DOMAIN,
        secure=False,
        rest={"HttpOnly": True},
    )
    return cookie_jar


@pytest.fixture()
def verified_cookie_set(cookie_jar: RequestsCookieJar) -> RequestsCookieJar:
    cookie_jar.set(
        name=settings.VERIFIED_COOKIE_NAME,
        value=settings.SIGNING.timed.dumps({"email": "verified@example.com"}),
        domain=settings.COOKIE_DOMAIN,
        secure=False,
        rest={"HttpOnly": True},
    )
    return cookie_jar


@pytest.fixture()
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


@pytest.fixture()
def valid_auth_signature() -> AuthSignature:
    return AuthSignature.create(
        email="someone@example.com", forward_headers=ForwardHeadersFactory.create()
    )
