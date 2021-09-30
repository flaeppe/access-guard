from __future__ import annotations

import argparse
import re
import sys

from .__version__ import __version__


def start_server() -> None:
    from access_guard import server

    server.run()


def command(argv: list[str] | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="access-guard", description="...")

    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument("-d", "--debug", dest="debug", action="store_true")
    parser.add_argument(
        "email_patterns",
        metavar="EMAIL_PATTERNS",
        # type is expecting a str, while re.compile expects a r"..."
        type=re.compile,  # type: ignore[arg-type]
        nargs="+",
        help="Email addresses to match, each compiled to a regex",
    )
    parser.add_argument("-s", "--secret", required=True, type=str, help="Secret key")
    # TODO: Validate auth_host is subdomain of cookie_domain
    parser.add_argument(
        "-a",
        "--auth-host",
        required=True,
        type=str,
        dest="auth_host",
        help="The entrypoint domain name for access guard (without protocol or path)",
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
    parser.add_argument(
        "-c",
        "--cookie-domain",
        required=True,
        type=str,
        dest="cookie_domain",
        help="...",
    )
    parser.add_argument(
        "--cookie-secure",
        action="store_true",
        dest="cookie_secure",
        help=(
            "Whether to only use secure cookies. When passed, cookies will be marked"
            " as 'secure' [default: false]"
        ),
    )
    # TODO: Take help text inspiration from Django
    parser.add_argument(
        "--email-host",
        required=True,
        type=str,
        dest="email_host",
        help="The host to use for sending emails",
    )
    parser.add_argument(
        "--email-port",
        required=True,
        type=int,
        dest="email_port",
        help="Port to use for the SMTP server defined in --email-host",
    )
    parser.add_argument(
        "--from-email",
        required=True,
        type=str,
        dest="from_email",
        help="What will become the sender's address in sent emails",
    )
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

    args = parser.parse_args(argv)
    assert args.email_patterns

    from access_guard.environ import environ

    environ.load(vars(args))
    start_server()
