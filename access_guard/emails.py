from email.message import EmailMessage

import aiosmtplib

from . import settings
from .schema import LoginSignature


def get_connection() -> aiosmtplib.SMTP:
    # TODO: Login with credentials
    return aiosmtplib.SMTP(
        hostname=settings.EMAIL_HOST,
        port=settings.EMAIL_PORT,
        # TODO: Support these(?)
        use_tls=None,
        start_tls=None,
        validate_certs=None,
    )


async def send_mail(signature: LoginSignature) -> None:
    message = EmailMessage()
    message["From"] = settings.FROM_EMAIL
    message["To"] = signature.email
    # TODO: Make subject come from a settings variable
    message["Subject"] = "The very secret code"
    message.set_content(f"{signature.code}")
    async with get_connection() as client:
        assert isinstance(client, aiosmtplib.SMTP)
        await client.send_message(message)
