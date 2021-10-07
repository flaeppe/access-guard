from email.message import EmailMessage

import aiosmtplib

from . import settings
from .templating import templates


def get_connection() -> aiosmtplib.SMTP:
    return aiosmtplib.SMTP(
        hostname=settings.EMAIL_HOST,
        port=settings.EMAIL_PORT,
        username=settings.EMAIL_USERNAME,
        password=str(settings.EMAIL_PASSWORD) if settings.EMAIL_PASSWORD else None,
        use_tls=settings.EMAIL_USE_TLS,
        start_tls=settings.EMAIL_START_TLS,
        validate_certs=settings.EMAIL_VALIDATE_CERTS,
        client_cert=settings.EMAIL_CLIENT_CERT,
        client_key=settings.EMAIL_CLIENT_KEY,
    )


async def send_mail(email: str, link: str, host_name: str) -> None:
    message = EmailMessage()
    message["From"] = settings.FROM_EMAIL
    message["To"] = email
    message["Subject"] = settings.EMAIL_SUBJECT
    template = templates.get_template("verification_email.txt")
    message.set_content(template.render(link=link, requested_service=host_name))
    async with get_connection() as client:
        assert isinstance(client, aiosmtplib.SMTP)
        await client.send_message(message)
