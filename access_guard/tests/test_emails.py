from unittest import mock

import pytest
from starlette.datastructures import URL

from ..emails import send_mail


@pytest.mark.asyncio()
async def test_can_send_auth_mail(mock_smtp_connection: mock.AsyncMock) -> None:
    await send_mail(
        email="someone@test.com", link=URL("http://something"), host_name="something"
    )
    mock_smtp_connection.send_message.assert_awaited_once()
