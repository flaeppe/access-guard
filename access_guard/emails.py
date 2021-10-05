from email.message import EmailMessage

import aiosmtplib

from . import settings


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


async def send_mail(email: str, link: str) -> None:
    message = EmailMessage()
    message["From"] = settings.FROM_EMAIL
    message["To"] = email
    message["Subject"] = settings.EMAIL_SUBJECT
    message.set_content(link)
    async with get_connection() as client:
        assert isinstance(client, aiosmtplib.SMTP)
        await client.send_message(message)
