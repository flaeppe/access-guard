import re
from io import StringIO
from unittest import mock

import pytest

from .. import cli

mock_run_server = mock.patch("access_guard.server.run", autospec=True)


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
    mock_load_environ = mock.patch("access_guard.environ.environ.load", autospec=True)
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
