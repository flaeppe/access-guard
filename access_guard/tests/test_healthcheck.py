from unittest import mock

import aiosmtplib
import pytest

from .. import healthcheck

mock_smtp_connection = mock.patch("aiosmtplib.SMTP", autospec=True)


class TestHealthcheck:
    @pytest.mark.asyncio()
    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(ValueError, id="value error"),
            pytest.param(aiosmtplib.SMTPException, id="smtp exception"),
        ],
    )
    async def test_command_exits_on_smtp_connect_raising(
        self, error: Exception
    ) -> None:
        with mock.patch.object(
            aiosmtplib.SMTP, "__aenter__", autospec=True
        ) as connection:
            connection.side_effect = error("failed")
            with pytest.raises(healthcheck.HealthcheckFailed):
                await healthcheck.check_smtp()

    @pytest.mark.asyncio()
    async def test_returns_true_on_valid_smtp_connection(self):
        with mock_smtp_connection as smtp_connection:
            await healthcheck.check_smtp()

        smtp_connection.assert_called_once_with(
            hostname="email-host",
            port=666,
            username=None,
            password=None,
            use_tls=False,
            start_tls=False,
            validate_certs=True,
            client_cert=None,
            client_key=None,
        )
