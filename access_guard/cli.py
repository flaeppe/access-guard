from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from pathlib import Path

from aiosmtplib.errors import SMTPException

from .log import logger


def command(argv: list[str] | None = None) -> None:
    from access_guard.environ import environ

    parsed = vars(parse_argv(argv if argv is not None else sys.argv[1:]))
    parsed["secret"] = (
        read_first_line(secret_file)
        if (secret_file := parsed.pop("secret_file", None))
        else parsed["secret"]
    )
    if email_password_file := parsed.pop("email_password_file", None):
        parsed["email_password"] = read_first_line(email_password_file)

    environ.load(parsed)

    if not healthcheck():
        exit(666)
    start_server()


def lowercase_regex_pattern(pattern: str) -> re.Pattern:
    return re.compile(f"{pattern.lower()}")


def parse_argv(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="access-guard", description="...")
    required = parser.add_argument_group(title="Required arguments")
    email_required = parser.add_argument_group(
        title="Required email arguments",
        description="SMTP/Email specific configuration",
    )
    email_optional = parser.add_argument_group(
        title="Optional email arguments",
        description="SMTP/Email specific configuration",
    )
    cookies_optional = parser.add_argument_group(
        title="Optional cookie arguments", description="Configuration for cookies"
    )
    # Positional arguments
    parser.add_argument(
        "email_patterns",
        metavar="EMAIL_PATTERN",
        type=lowercase_regex_pattern,
        nargs="+",
        help="Email addresses to match, each compiled to a regex",
    )
    # Required arguments
    secret_mutex = required.add_mutually_exclusive_group(required=True)
    secret_mutex.add_argument(
        "-s", "--secret", type=str, dest="secret", help="Secret key"
    )
    secret_mutex.add_argument(
        "-sf",
        "--secret-file",
        type=Path,
        dest="secret_file",
        metavar="PATH_TO_FILE",
        help="Secret key file",
    )
    # TODO: Validate auth_host is subdomain of cookie_domain
    required.add_argument(
        "-a",
        "--auth-host",
        required=True,
        type=str,
        dest="auth_host",
        help="The entrypoint domain name for access guard (without protocol or path)",
    )
    required.add_argument(
        "-t",
        "--trusted-hosts",
        required=True,
        metavar="TRUSTED_HOST",
        type=str,
        nargs="+",
        help=(
            "Hosts/domain names that access guard should serve. Matched against a"
            " request's Host header. Wildcard domains such as '*.example.com' are"
            " supported for matching subdomains. To allow any hostname use: *"
        ),
    )
    # TODO: Support auth token
    # parser.add_argument(
    #    "-t",
    #    "--auth-token",
    #    required=False,
    #    type=str,
    #    default=None,
    #    dest="auth_token",
    #    help=(
    #        "Value that is expected in an Authorization: Token <AUTH TOKEN> header on"
    #        " requests to access guard"
    #    ),
    # )
    required.add_argument(
        "-c",
        "--cookie-domain",
        required=True,
        type=str,
        dest="cookie_domain",
        help=(
            "The domain to use for cookies. Ensure this value covers domain set"
            " for AUTH_HOST"
        ),
    )
    # Optional arguments
    version = os.environ.get("ACCESS_GUARD_BUILD_VERSION") or "N/A"
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {version}"
    )
    parser.add_argument("-d", "--debug", dest="debug", action="store_true")
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",  # nosec
        help="Server host. [default: 0.0.0.0]",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8585,
        help="Server port. [default: 8585]",
    )
    # Required email arguments
    email_required.add_argument(
        "--email-host",
        required=True,
        type=str,
        dest="email_host",
        help="The host to use for sending emails",
    )
    email_required.add_argument(
        "--email-port",
        required=True,
        type=int,
        dest="email_port",
        help="Port to use for the SMTP server defined in --email-host",
    )
    email_required.add_argument(
        "--from-email",
        required=True,
        type=str,
        dest="from_email",
        help="What will become the sender's address in sent emails",
    )
    # Optional email arguments
    email_optional.add_argument(
        "--email-username",
        type=str,
        dest="email_username",
        default=argparse.SUPPRESS,
        help="Username to login with on configured SMTP server [default: unset]",
    )
    email_password_mutex = email_optional.add_mutually_exclusive_group()
    email_password_mutex.add_argument(
        "--email-password",
        type=str,
        dest="email_password",
        default=argparse.SUPPRESS,
        help="Password to login with on configured SMTP server [default: unset]",
    )
    email_password_mutex.add_argument(
        "--email-password-file",
        type=Path,
        dest="email_password_file",
        metavar="PATH_TO_FILE",
        default=argparse.SUPPRESS,
        help=(
            "File containing password to login with on configured SMTP server"
            " [default: unset]"
        ),
    )
    email_tls_mutex = email_optional.add_mutually_exclusive_group()
    email_tls_mutex.add_argument(
        "--email-use-tls",
        dest="email_use_tls",
        action="store_true",
        help=(
            "Make the _initial_ connection to the SMTP server over TLS/SSL"
            " [default: false]"
        ),
    )
    email_tls_mutex.add_argument(
        "--email-start-tls",
        dest="email_start_tls",
        action="store_true",
        help=(
            "Make the initial connection to the SMTP server over plaintext,"
            " and then upgrade the connection to TLS/SSL [default: false]"
        ),
    )
    email_optional.add_argument(
        "--email-no-validate-certs",
        dest="email_validate_certs",
        action="store_false",
        help="Disable validating server certificates for SMTP [default: false]",
    )
    email_optional.add_argument(
        "--email-client-cert",
        type=Path,
        dest="email_client_cert",
        default=argparse.SUPPRESS,
        help="Path to client side certificate, for TLS verification [default: unset]",
    )
    email_optional.add_argument(
        "--email-client-key",
        type=Path,
        dest="email_client_key",
        default=argparse.SUPPRESS,
        help="Path to client side key, for TLS verification [default: unset]",
    )
    email_optional.add_argument(
        "--email-subject",
        type=str,
        dest="email_subject",
        default="Access guard verification",
        help=(
            "Subject of the email sent for verification"
            " [default: Access guard verification]"
        ),
    )
    # Optional cookie arguments
    cookies_optional.add_argument(
        "--cookie-secure",
        action="store_true",
        dest="cookie_secure",
        help=(
            "Whether to only use secure cookies. When passed, cookies will be marked"
            " as 'secure' [default: false]"
        ),
    )
    cookies_optional.add_argument(
        "--auth-cookie-name",
        dest="auth_cookie_name",
        default="access-guard-forwarded",
        help=(
            "Name for cookie used during auth flow [default: access-guard-forwarded]"
        ),
    )
    cookies_optional.add_argument(
        "--verified-cookie-name",
        dest="verified_cookie_name",
        default="access-guard-session",
        help=(
            "Name for cookie set when auth completed successfully"
            " [default: access-guard-session]"
        ),
    )
    cookies_optional.add_argument(
        "--auth-cookie-max-age",
        dest="auth_cookie_max_age",
        default=argparse.SUPPRESS,
        help=(
            "Seconds before the cookie set _during_ auth flow should expire"
            " [default: 3600 (1 hour)]"
        ),
    )
    cookies_optional.add_argument(
        "--auth-signature-max-age",
        dest="auth_signature_max_age",
        default=argparse.SUPPRESS,
        help=(
            "Decides how many seconds a verification email should be valid. When"
            " the amount of seconds has passed, the client has to request a new email."
            " [default: 600 (10 minutes)]"
        ),
    )
    cookies_optional.add_argument(
        "--verify-signature-max-age",
        dest="verify_signature_max_age",
        default=argparse.SUPPRESS,
        help=(
            "Decides how many seconds a verified session cookie should be valid. When"
            " the amount of seconds has passed, the client has to verify again."
            " [default: 86400 (24 hours)]"
        ),
    )

    args = parser.parse_args(argv)
    assert args.email_patterns
    return args


def start_server() -> None:
    from access_guard import server

    server.run()


def read_first_line(path: Path) -> str:
    with path.open() as f:
        value = f.readline().rstrip("\n")

    if not value:
        sys.stderr.write(f"Encountered empty first line in {str(path)}\n")
        sys.exit(2)

    return value


class HealthcheckFailed(Exception):
    ...


async def _check_smtp() -> None:
    from access_guard.emails import get_connection

    try:
        async with get_connection():
            ...
    except (ValueError, SMTPException) as exc:
        raise HealthcheckFailed("Failed to establish an SMTP connection") from exc


def healthcheck() -> bool:
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(_check_smtp())
    except HealthcheckFailed as exc:
        logger.critical(str(exc), exc_info=True)
        return False

    logger.info("healthcheck.success")
    return True
