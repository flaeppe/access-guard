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
        "auth_host": "testserver.local",
        "cookie_domain": "testserver.local",
        "email_host": "mailhog",
        "email_port": "1025",
        "from_email": "access-guard@local.com",
    }
)

from .. import server, settings  # noqa: E402
from ..schema import LoginSignature  # noqa: E402
from .factories import ForwardHeadersFactory  # noqa: E402


@pytest.fixture(scope="function")
async def api_client() -> AsyncGenerator[TestClient, None]:
    with mock.patch("uvicorn.run", autospec=True):
        server.run()
        with TestClient(server.app, base_url=f"http://{settings.DOMAIN}") as client:
            yield client


@pytest.fixture(scope="function")
def login_cookie_set() -> RequestsCookieJar:
    cookie_jar = RequestsCookieJar()
    cookie_jar.set(
        name="access-guard-forwarded",
        value=ForwardHeadersFactory.create().encode(),
        domain=settings.DOMAIN,
        secure=False,
        rest={"HttpOnly": True},
    )
    return cookie_jar


@pytest.fixture(scope="function")
def expired_login_cookie_set() -> RequestsCookieJar:
    cookie_jar = RequestsCookieJar()
    cookie_jar.set(
        name="access-guard-forwarded",
        value=ForwardHeadersFactory.create().encode(),
        domain=settings.DOMAIN,
        expires=-1,
        secure=False,
        rest={"HttpOnly": True},
    )
    return cookie_jar


@pytest.fixture(scope="session")
def auth_url() -> str:
    return "/auth"


@pytest.fixture(scope="function")
def valid_verification() -> tuple[LoginSignature, RequestsCookieJar]:
    headers = ForwardHeadersFactory.create()
    cookies = RequestsCookieJar()
    cookies.set(
        name="access-guard-forwarded",
        value=headers.encode(),
        domain=settings.DOMAIN,
        secure=False,
        rest={"HttpOnly": True},
    )
    login_signature = LoginSignature.create(email="someone@test.com", valid_code=True)
    return login_signature, cookies
