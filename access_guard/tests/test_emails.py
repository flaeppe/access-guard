from typing import Generator
from unittest import mock

import aiosmtplib
import pytest

from ..emails import send_mail
from ..schema import LoginSignature


@pytest.fixture(scope="function")
def mock_smtp_connection() -> Generator[mock.AsyncMock, None, None]:
    context_mock = mock.AsyncMock(spec_set=aiosmtplib.SMTP)
    with mock.patch("aiosmtplib.SMTP.__aenter__", autospec=True) as connection:
        connection.return_value = context_mock
        yield context_mock


@pytest.mark.asyncio
async def test_can_send_login_mail(mock_smtp_connection: mock.AsyncMock) -> None:
    await send_mail(
        LoginSignature(
            email="someone@email.com",
            code="001337",
            signature="secret",
        ),
    )
    mock_smtp_connection.send_message.assert_awaited_once()
