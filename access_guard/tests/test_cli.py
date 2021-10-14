import itertools
import os
import re
from contextlib import ExitStack
from io import StringIO
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from aiosmtplib.errors import SMTPException

from .. import cli

mock_load_environ = mock.patch("access_guard.environ.environ.load", autospec=True)
mock_run_server = mock.patch("access_guard.server.run", autospec=True)
mock_smtp_connection = mock.patch("aiosmtplib.SMTP", autospec=True)
mock_stderr = mock.patch("argparse._sys.stderr", new_callable=StringIO)
successful_healthcheck = mock.patch(
    "access_guard.cli.healthcheck", autospec=True, return_value=True
)


@pytest.fixture(scope="function")
def valid_command_args() -> tuple[list[str], dict[str, Any]]:
    return (
        [
            ".*",
            "--secret",
            "supersecret",
            "--auth-host",
            "valid.local",
            "--trusted-hosts",
            "valid.local",
            "--cookie-domain",
            "valid.local",
            "--email-host",
            "email-host",
            "--email-port",
            "666",
            "--from-email",
            "webmaster@local.com",
        ],
        {
            "debug": False,
            "email_patterns": [re.compile(r".*")],
            "secret": "supersecret",
            "auth_host": "valid.local",
            "trusted_hosts": ["valid.local"],
            "cookie_domain": "valid.local",
            "cookie_secure": False,
            "auth_cookie_name": "access-guard-forwarded",
            "verified_cookie_name": "access-guard-session",
            "email_host": "email-host",
            "email_port": 666,
            "from_email": "webmaster@local.com",
            "email_use_tls": False,
            "email_start_tls": False,
            "email_validate_certs": True,
            "email_subject": "Access guard verification",
            "host": "0.0.0.0",
            "port": 8585,
        },
    )


@pytest.mark.parametrize(
    "argv", (["-V"], ["--version"]), ids=["short name", "long name"]
)
def test_version_from(argv: list[str]) -> None:
    version = "0.0.0-test"
    with ExitStack() as stack:
        stack.enter_context(
            mock.patch.dict(
                os.environ, {"ACCESS_GUARD_BUILD_VERSION": version}, clear=True
            )
        )
        cm = stack.enter_context(pytest.raises(SystemExit))
        run_server = stack.enter_context(mock_run_server)
        stdout = stack.enter_context(
            mock.patch("argparse._sys.stdout", new_callable=StringIO)
        )
        cli.command(argv)

    run_server.assert_not_called()
    assert cm.value.code == 0
    assert f"access-guard {version}" in stdout.getvalue()


@pytest.mark.parametrize(
    "required_arg,error_msg_match",
    (
        pytest.param("email_patterns", "EMAIL_PATTERN", id="email patterns"),
        pytest.param("--secret", "-s/--secret", id="secret"),
        pytest.param("--auth-host", "-a/--auth-host", id="auth host"),
        pytest.param("--trusted-hosts", "-t/--trusted-hosts", id="trusted hosts"),
        pytest.param("--cookie-domain", "-c/--cookie-domain", id="cookie domain"),
        pytest.param("--email-host", "--email-host", id="email host"),
        pytest.param("--email-port", "--email-port", id="email port"),
        pytest.param("--from-email", "--from-email", id="from email"),
    ),
)
def test_arg_is_required(required_arg: str, error_msg_match: str) -> None:
    required = {
        "email_patterns": ".*",
        "--secret": "supersecret",
        "--auth-host": "valid.local",
        "--trusted-hosts": "valid.local",
        "--cookie-domain": "valid.local",
        "--email-host": "email-host",
        "--email-port": "666",
        "--from-email": "webmaster@local.com",
    }
    required.pop(required_arg)
    with pytest.raises(
        SystemExit
    ) as cm, mock_run_server as run_server, mock_stderr as stderr:
        cli.command(
            list(
                itertools.chain.from_iterable(
                    [
                        ((name, value) if name != "email_patterns" else (value,))
                        for name, value in required.items()
                    ]
                )
            )
        )

    run_server.assert_not_called()
    assert cm.value.code == 2
    assert (
        re.search(rf".*arguments are required: {error_msg_match}.*", stderr.getvalue())
        is not None
    )


def test_email_patterns_are_forced_lowercase(
    valid_command_args: tuple[list[str], dict[str, Any]]
) -> None:
    argv, parsed_argv = valid_command_args
    with ExitStack() as stack:
        run_server = stack.enter_context(mock_run_server)
        load_environ = stack.enter_context(mock_load_environ)
        stack.enter_context(successful_healthcheck)
        cli.command([".*@PaTtErN.CoM", *argv[1:]])

    run_server.assert_called_once()
    parsed_argv.pop("email_patterns")
    load_environ.assert_called_once_with(
        {"email_patterns": [re.compile(r".*@pattern.com")], **parsed_argv},
    )


def test_defaults() -> None:
    with ExitStack() as stack:
        run_server = stack.enter_context(mock_run_server)
        load_environ = stack.enter_context(mock_load_environ)
        stack.enter_context(successful_healthcheck)
        cli.command(
            [
                ".*@defaults.com",
                "--secret",
                "a secret",
                "--auth-host",
                "testing-defaults.local",
                "--trusted-hosts",
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
            "trusted_hosts": ["testing-defaults.local"],
            "cookie_domain": "testing-defaults.local",
            "cookie_secure": False,
            "auth_cookie_name": "access-guard-forwarded",
            "verified_cookie_name": "access-guard-session",
            "email_host": "email-host",
            "email_port": 666,
            "from_email": "webmaster@local.com",
            "email_use_tls": False,
            "email_start_tls": False,
            "email_validate_certs": True,
            "email_subject": "Access guard verification",
            "host": "0.0.0.0",
            "port": 8585,
        }
    )


def test_email_use_tls_and_start_tls_are_mutually_exclusive(
    valid_command_args: tuple[list[str], dict[str, Any]]
) -> None:
    argv, __ = valid_command_args
    with pytest.raises(
        SystemExit
    ) as cm, mock_run_server as run_server, mock_stderr as stderr:
        cli.command([*argv, "--email-use-tls", "--email-start-tls"])

    assert cm.value.code == 2
    msg_regex = r".*--email-start-tls.*not allowed with argument.*--email-use-tls.*"
    assert re.search(msg_regex, stderr.getvalue()) is not None
    run_server.assert_not_called()


def test_email_client_cert_and_key_parsed_as_path(
    valid_command_args: tuple[list[str], dict[str, Any]]
) -> None:
    argv, parsed_argv = valid_command_args
    with ExitStack() as stack:
        run_server = stack.enter_context(mock_run_server)
        load_environ = stack.enter_context(mock_load_environ)
        stack.enter_context(successful_healthcheck)
        cli.command(
            [
                *argv,
                "--email-client-cert",
                "path/to/cert.cert",
                "--email-client-key",
                "path/to/key.key",
            ]
        )

    run_server.assert_called_once()
    load_environ.assert_called_once_with(
        {
            **parsed_argv,
            "email_client_cert": Path("path/to/cert.cert"),
            "email_client_key": Path("path/to/key.key"),
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
        argv, __ = valid_command_args
        # TODO: Black seems to have troubles parsing multiline with..
        with ExitStack() as stack:
            stack.enter_context(mock_load_environ)
            run_server = stack.enter_context(mock_run_server)
            smtp_connection = stack.enter_context(mock_smtp_connection)
            cm = stack.enter_context(pytest.raises(SystemExit))

            smtp_connection.side_effect = error("failed")
            cli.command(argv)

        assert cm.value.code == 666
        run_server.assert_not_called()

    def test_returns_true_on_valid_smtp_connection(self):
        with mock_smtp_connection as smtp_connection:
            result = cli.healthcheck()

        assert result is True
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
