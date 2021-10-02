import re
from contextlib import ExitStack
from io import StringIO
from unittest import mock

import pytest
from aiosmtplib.errors import SMTPException

from .. import cli

mock_load_environ = mock.patch("access_guard.environ.environ.load", autospec=True)
mock_run_server = mock.patch("access_guard.server.run", autospec=True)
mock_smtp_connection = mock.patch("access_guard.emails.get_connection", autospec=True)


@pytest.fixture(scope="session")
def valid_command_args() -> list[str]:
    return [
        ".*",
        "--secret",
        "supersecret",
        "--auth-host",
        "valid.local",
        "--cookie-domain",
        "valid.local",
        "--email-host",
        "email-host",
        "--email-port",
        "666",
        "--from-email",
        "webmaster@local.com",
    ]


@pytest.mark.parametrize(
    "argv", (["-V"], ["--version"]), ids=["short name", "long name"]
)
def test_version_from(argv: list[str]) -> None:
    mock_stdout = mock.patch("argparse._sys.stdout", new_callable=StringIO)
    with pytest.raises(
        SystemExit
    ) as cm, mock_run_server as run_server, mock_stdout as stdout:
        cli.command(argv)

    run_server.assert_not_called()
    assert cm.value.code == 0
    assert "access-guard 0.1" in stdout.getvalue()


def test_email_patterns_are_required() -> None:
    mock_stderr = mock.patch("argparse._sys.stderr", new_callable=StringIO)
    with pytest.raises(
        SystemExit
    ) as cm, mock_run_server as run_server, mock_stderr as stderr:
        cli.command([])

    run_server.assert_not_called()
    assert cm.value.code == 2
    assert (
        re.search(r".*arguments are required: EMAIL_PATTERNS.*", stderr.getvalue())
        is not None
    )


def test_defaults() -> None:
    with mock_run_server as run_server, mock_load_environ as load_environ:
        cli.command(
            [
                ".*@defaults.com",
                "--secret",
                "a secret",
                "--auth-host",
                "testing-defaults.local",
                "--cookie-domain",
                "testing-defaults.local",
                "--email-host",
                "email-host",
                "--email-port",
                "666",
                "--from-email",
                "webmaster@local.com",
            ],
        )

    run_server.assert_called_once()
    load_environ.assert_called_once_with(
        {
            "debug": False,
            "email_patterns": [re.compile(r".*@defaults.com")],
            "secret": "a secret",
            "auth_host": "testing-defaults.local",
            "cookie_domain": "testing-defaults.local",
            "cookie_secure": False,
            "login_cookie_name": "access-guard-forwarded",
            "verified_cookie_name": "access-guard-session",
            "email_host": "email-host",
            "email_port": 666,
            "from_email": "webmaster@local.com",
            "host": "0.0.0.0",
            "port": 8585,
        }
    )


class TestHealthcheck:
    @pytest.mark.parametrize(
        "error",
        (
            pytest.param(ValueError, id="value error"),
            pytest.param(SMTPException, id="smtp exception"),
        ),
    )
    def test_command_exits_on_smtp_connect_raising(
        self, error: Exception, valid_command_args: list[str]
    ) -> None:
        # TODO: Black seems to have troubles parsing multiline with..
        with ExitStack() as stack:
            stack.enter_context(mock_load_environ)
            run_server = stack.enter_context(mock_run_server)
            smtp_connection = stack.enter_context(mock_smtp_connection)
            cm = stack.enter_context(pytest.raises(SystemExit))

            smtp_connection.side_effect = error("failed")
            cli.command(valid_command_args)

        assert cm.value.code == 666
        run_server.assert_not_called()

    def test_returns_true_on_valid_smtp_connection(self):
        with mock_smtp_connection as smtp_connection:
            result = cli.healthcheck()

        assert result is True
        smtp_connection.assert_called_once_with()
