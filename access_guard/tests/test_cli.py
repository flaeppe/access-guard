from __future__ import annotations

import itertools
import os
import re
from contextlib import ExitStack, contextmanager
from io import StringIO
from pathlib import Path
from typing import Any, Generator
from unittest import mock

import pytest
from aiosmtplib.errors import SMTPException
from starlette.datastructures import URL

from .. import cli

mock_load_environ = mock.patch("access_guard.environ.environ.load", autospec=True)
mock_run_server = mock.patch("access_guard.server.run", autospec=True)
mock_smtp_connection = mock.patch("aiosmtplib.SMTP", autospec=True)
mock_stderr = mock.patch("argparse._sys.stderr", new_callable=StringIO)
successful_healthcheck = mock.patch(
    "access_guard.cli.healthcheck", autospec=True, return_value=True
)


@pytest.fixture()
def valid_command_args() -> tuple[dict[str, str], dict[str, Any]]:
    return (
        {
            "email_patterns": ".*",
            "--secret": "supersecret",
            "--auth-host": "http://valid.local/",
            "--trusted-hosts": "valid.local",
            "--cookie-domain": "valid.local",
            "--email-host": "email-host",
            "--email-port": "666",
            "--from-email": "webmaster@local.com",
        },
        {
            "debug": False,
            "email_patterns": [re.compile(r".*")],
            "secret": "supersecret",
            "auth_host": "http://valid.local/",
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


def dict_to_argv(
    args: dict[str, str], positionals: set[str] | None = None
) -> list[str]:
    return list(
        itertools.chain.from_iterable(
            [
                ((name, value) if name not in (positionals or set()) else (value,))
                for name, value in args.items()
            ]
        )
    )


@contextmanager
def exiting_from_parse(exit_code: int = 2) -> Generator[mock.MagicMock, None, None]:
    with pytest.raises(
        SystemExit
    ) as cm, mock_run_server as run_server, mock_stderr as stderr:
        yield stderr

    run_server.assert_not_called()
    assert cm.value.code == exit_code


@contextmanager
def mock_successful_startup() -> Generator[mock.MagicMock, None, None]:
    with mock_run_server as run_server:
        with mock_load_environ as load_environ:
            with successful_healthcheck:
                yield load_environ

    run_server.assert_called_once()


@pytest.mark.parametrize(
    "argv", [("-V",), ("--version",)], ids=["short name", "long name"]
)
def test_version_from(argv: list[str]) -> None:
    version = "0.0.0-test"
    mock_environ = mock.patch.dict(
        os.environ, {"ACCESS_GUARD_BUILD_VERSION": version}, clear=True
    )
    mock_stdout = mock.patch("argparse._sys.stdout", new_callable=StringIO)
    with exiting_from_parse(exit_code=0), mock_environ, mock_stdout as stdout:
        cli.command(argv)

    assert f"access-guard {version}" in stdout.getvalue()


@pytest.mark.parametrize(
    ("required_arg", "error_msg_match"),
    [
        pytest.param("email_patterns", "EMAIL_PATTERN", id="email patterns"),
        pytest.param("--auth-host", "-a/--auth-host", id="auth host"),
        pytest.param("--trusted-hosts", "-t/--trusted-hosts", id="trusted hosts"),
        pytest.param("--cookie-domain", "-c/--cookie-domain", id="cookie domain"),
        pytest.param("--email-host", "--email-host", id="email host"),
        pytest.param("--email-port", "--email-port", id="email port"),
        pytest.param("--from-email", "--from-email", id="from email"),
    ],
)
def test_arg_is_required(required_arg: str, error_msg_match: str) -> None:
    required = {
        "email_patterns": ".*",
        "--secret": "supersecret",
        "--auth-host": "http://valid.local",
        "--trusted-hosts": "valid.local",
        "--cookie-domain": "valid.local",
        "--email-host": "email-host",
        "--email-port": "666",
        "--from-email": "webmaster@local.com",
    }
    required.pop(required_arg)
    with exiting_from_parse() as stderr:
        cli.command(dict_to_argv(required, positionals={"email_patterns"}))

    assert (
        re.search(rf".*arguments are required: {error_msg_match}.*", stderr.getvalue())
        is not None
    )


def test_secret_or_secret_file_arg_is_required(
    valid_command_args: tuple[dict[str, str], dict[str, Any]]
) -> None:
    argv, __ = valid_command_args
    argv.pop("--secret")
    with exiting_from_parse() as stderr:
        cli.command(dict_to_argv(argv, positionals={"email_patterns"}))

    assert re.search(
        r".*one of the arguments -s/--secret -sf/--secret-file is required",
        stderr.getvalue(),
    )


def test_email_patterns_are_forced_lowercase(
    valid_command_args: tuple[dict[str, str], dict[str, Any]]
) -> None:
    argv, parsed_argv = valid_command_args
    argv.pop("email_patterns")
    parsed_argv.pop("email_patterns")
    with mock_successful_startup() as load_environ:
        cli.command([".*@PaTtErN.CoM", *dict_to_argv(argv)])

    load_environ.assert_called_once_with(
        {"email_patterns": [re.compile(r".*@pattern.com")], **parsed_argv},
    )


def test_defaults() -> None:
    with mock_successful_startup() as load_environ:
        cli.command(
            [
                ".*@defaults.com",
                "--secret",
                "a secret",
                "--auth-host",
                "http://testing-defaults.local/",
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

    load_environ.assert_called_once_with(
        {
            "debug": False,
            "email_patterns": [re.compile(r".*@defaults.com")],
            "secret": "a secret",
            "auth_host": "http://testing-defaults.local/",
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


@pytest.mark.parametrize(
    ("additional_args", "msg_regex"),
    [
        pytest.param(
            ["--secret-file", "some/file"],
            r".*-sf/--secret-file.*not allowed with argument.*-s/--secret",
            id="secret and secret file",
        ),
        pytest.param(
            ["--email-use-tls", "--email-start-tls"],
            r".*--email-start-tls.*not allowed with argument.*--email-use-tls.*",
            id="email use tls and email start tls",
        ),
        pytest.param(
            ["--email-password", "supersecret", "--email-password-file", "some/file"],
            r".*--email-password-file.*not allowed with argument.*--email-password",
            id="email password and email password file",
        ),
    ],
)
def test_mutually_exclusive_args(
    additional_args: list[str],
    msg_regex: str,
    valid_command_args: tuple[dict[str, str], dict[str, Any]],
) -> None:
    argv, __ = valid_command_args
    with exiting_from_parse() as stderr:
        cli.command(
            [*dict_to_argv(argv, positionals={"email_patterns"}), *additional_args]
        )

    assert re.search(msg_regex, stderr.getvalue()) is not None


def test_email_client_cert_and_key_parsed_as_path(
    valid_command_args: tuple[dict[str, str], dict[str, Any]]
) -> None:
    argv, parsed_argv = valid_command_args
    with mock_successful_startup() as load_environ:
        cli.command(
            [
                *dict_to_argv(argv, positionals={"email_patterns"}),
                "--email-client-cert",
                "path/to/cert.cert",
                "--email-client-key",
                "path/to/key.key",
            ]
        )

    load_environ.assert_called_once_with(
        {
            **parsed_argv,
            "email_client_cert": Path("path/to/cert.cert"),
            "email_client_key": Path("path/to/key.key"),
        }
    )


@pytest.mark.parametrize(
    ("read_data", "expected"),
    [
        pytest.param("secretfromfile", "secretfromfile", id="no trailing space"),
        pytest.param(
            "secretfromfile\n", "secretfromfile", id="content ending with newline"
        ),
        pytest.param(
            "secretfromfile  ", "secretfromfile  ", id="content ending with spaces"
        ),
        pytest.param(
            "secretfromfile  \n",
            "secretfromfile  ",
            id="content ending with spaces and newline",
        ),
        pytest.param(
            "secretfromfile\nshouldbeignored", "secretfromfile", id="multiple lines"
        ),
        pytest.param(" ", " ", id="only spaces"),
    ],
)
def test_can_load_args_from_file_with(
    read_data: str,
    expected: str,
    valid_command_args: tuple[dict[str, str], dict[str, Any]],
) -> None:
    argv, parsed_argv = valid_command_args
    argv.pop("--secret")
    parsed_argv.pop("secret")
    mock_path_open = mock.patch(
        "pathlib.Path.open", mock.mock_open(read_data=read_data)
    )
    with mock_successful_startup() as load_environ, mock_path_open as open_file:
        cli.command(
            [
                *dict_to_argv(argv, positionals={"email_patterns"}),
                "--secret-file",
                "secret/file",
                "--email-password-file",
                "password/file",
            ]
        )

    assert open_file.call_count == 2
    load_environ.assert_called_once_with(
        {**parsed_argv, "secret": expected, "email_password": expected}
    )


@pytest.mark.parametrize(
    "file_contents",
    [
        pytest.param("", id="be empty"),
        pytest.param("\n", id="be sole newline character"),
        pytest.param("\nsomething", id="have an empty first line"),
    ],
)
def test_secret_file_content_can_not(
    file_contents: str,
    valid_command_args: tuple[dict[str, str], dict[str, Any]],
) -> None:
    argv, parsed_argv = valid_command_args
    argv.pop("--secret")
    parsed_argv.pop("secret")
    mock_path_open = mock.patch(
        "pathlib.Path.open", mock.mock_open(read_data=file_contents)
    )
    with exiting_from_parse() as stderr, mock_path_open as open_file:
        cli.command(
            [
                *dict_to_argv(argv, positionals={"email_patterns"}),
                "--secret-file",
                "secret/file",
            ]
        )

    open_file.assert_called_once_with()
    assert (
        re.search(r".*empty first line in secret/file.*", stderr.getvalue()) is not None
    )


@pytest.mark.parametrize(
    "file_contents",
    [
        pytest.param("", id="be empty"),
        pytest.param("\n", id="be sole newline character"),
        pytest.param("\nsomething", id="have an empty first line"),
    ],
)
def test_email_password_file_content_can_not(
    file_contents: str,
    valid_command_args: tuple[dict[str, str], dict[str, Any]],
) -> None:
    argv, parsed_argv = valid_command_args
    mock_path_open = mock.patch(
        "pathlib.Path.open", mock.mock_open(read_data=file_contents)
    )
    with exiting_from_parse() as stderr, mock_path_open as open_file:
        cli.command(
            [
                *dict_to_argv(argv, positionals={"email_patterns"}),
                "--email-password-file",
                "email/password/file",
            ]
        )

    open_file.assert_called_once_with()
    assert (
        re.search(r".*empty first line in email/password/file.*", stderr.getvalue())
        is not None
    )


class TestHealthcheck:
    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(ValueError, id="value error"),
            pytest.param(SMTPException, id="smtp exception"),
        ],
    )
    def test_command_exits_on_smtp_connect_raising(
        self,
        error: Exception,
        valid_command_args: tuple[dict[str, str], dict[str, Any]],
    ) -> None:
        argv, __ = valid_command_args
        # TODO: Black seems to have troubles parsing multiline with..
        with ExitStack() as stack:
            stack.enter_context(mock_load_environ)
            run_server = stack.enter_context(mock_run_server)
            smtp_connection = stack.enter_context(mock_smtp_connection)
            cm = stack.enter_context(pytest.raises(SystemExit))

            smtp_connection.side_effect = error("failed")
            cli.command(dict_to_argv(argv, positionals={"email_patterns"}))

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


class TestAuthHost:
    @pytest.mark.parametrize(
        ("value", "msg_regex"),
        [
            pytest.param(
                "://example.com/",
                r".*either 'http' or 'https', got: ''.*",
                id="missing_protocol",
            ),
            pytest.param(
                "example.com/path",
                r".*either 'http' or 'https', got: ''.*",
                id="missing_protocol_and_separators",
            ),
            pytest.param(
                "file:///some/path",
                r".*either 'http' or 'https', got: 'file'.*",
                id="protocol_is_non_http",
            ),
            pytest.param(
                "http:///path", r".*is missing a domain.*", id="missing_domain"
            ),
            pytest.param(
                "example.com",
                r".*either 'http' or 'https', got: ''.*",
                id="missing_protocol_and_path",
            ),
        ],
    )
    def test_parsing_fails_when(
        self,
        value: str,
        msg_regex: str,
        valid_command_args: tuple[dict[str, str], dict[str, Any]],
    ):
        argv, __ = valid_command_args
        argv["--auth-host"] = value
        with exiting_from_parse() as stderr:
            cli.command(dict_to_argv(argv, positionals={"email_patterns"}))

        assert re.search(msg_regex, stderr.getvalue())

    def test_can_parse_with_path_and_query_params(
        self, valid_command_args: tuple[dict[str, str], dict[str, Any]]
    ):
        argv, parsed_argv = valid_command_args
        argv["--auth-host"] = "http://example.com/path/?query=param#fragment"
        with mock_successful_startup() as load_environ:
            cli.command(dict_to_argv(argv, positionals={"email_patterns"}))

        load_environ.assert_called_once_with(
            {**parsed_argv, "auth_host": URL(argv["--auth-host"])}
        )

    def test_forces_trailing_slash(
        self, valid_command_args: tuple[dict[str, str], dict[str, Any]]
    ):
        argv, parsed_argv = valid_command_args
        argv["--auth-host"] = "http://example.com/path?query=param#fragment"
        with mock_successful_startup() as load_environ:
            cli.command(dict_to_argv(argv, positionals={"email_patterns"}))

        load_environ.assert_called_once_with(
            {
                **parsed_argv,
                "auth_host": URL("http://example.com/path/?query=param#fragment"),
            }
        )
