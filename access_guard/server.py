from __future__ import annotations

from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from . import healthcheck, settings
from .log import LOGGING_CONFIG, logger
from .routes.auth import auth
from .routes.send import send
from .routes.verify import verify


async def log_settings() -> None:
    logger.info(
        "loaded_config",
        email_patterns=[compiled.pattern for compiled in settings.EMAIL_PATTERNS],
        auth_host=str(settings.AUTH_HOST),
        cookie_domain=settings.COOKIE_DOMAIN,
        cookie_secure=settings.COOKIE_SECURE,
        email_host=settings.EMAIL_HOST,
        email_port=settings.EMAIL_PORT,
        auth_cookie_name=settings.AUTH_COOKIE_NAME,
        verified_cookie_name=settings.VERIFIED_COOKIE_NAME,
        auth_cookie_max_age=settings.AUTH_COOKIE_MAX_AGE,
        auth_signature_max_age=settings.AUTH_SIGNATURE_MAX_AGE,
        verify_signature_max_age=settings.VERIFY_SIGNATURE_MAX_AGE,
        host=settings.HOST,
        port=settings.PORT,
        debug=settings.DEBUG,
    )


routes = [
    Mount(
        settings.AUTH_HOST.path,
        routes=[
            Route("/auth", endpoint=auth, methods=["GET", "POST"], name="auth"),
            Route("/send", endpoint=send, methods=["GET", "POST"], name="send"),
            Route(
                "/verify/{signature:str}",
                endpoint=verify,
                methods=["GET"],
                name="verify",
            ),
            Mount(
                "/static",
                app=StaticFiles(directory=str(Path(__file__).parent / "static")),
                name="static",
            ),
        ],
    ),
]
middleware = [
    Middleware(TrustedHostMiddleware, allowed_hosts=settings.TRUSTED_HOSTS),
]
app = Starlette(
    routes=routes,
    middleware=middleware,
    debug=settings.DEBUG,
    on_startup=[log_settings, healthcheck.check_smtp],
)


def run() -> None:  # pragma: no cover
    import uvicorn

    uvicorn.run(
        app,
        host=settings.HOST,
        port=settings.PORT,
        proxy_headers=True,
        log_config=LOGGING_CONFIG,
    )
