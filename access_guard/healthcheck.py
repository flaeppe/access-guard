from aiosmtplib.errors import SMTPException

from .log import logger


class HealthcheckFailed(Exception):
    ...


async def check_smtp() -> None:
    from access_guard.emails import get_connection

    try:
        async with get_connection():
            ...
    except (ValueError, SMTPException) as exc:
        logger.warning("check_smtp.failed", exc_info=True)
        raise HealthcheckFailed("Failed to establish an SMTP connection") from exc
