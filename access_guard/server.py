from __future__ import annotations

from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from . import settings
from .routes.auth import auth
from .routes.send import send
from .routes.verify import verify

routes = [
    Route("/auth", endpoint=auth, methods=["GET", "POST"], name="auth"),
    Route("/send", endpoint=send, methods=["GET", "POST"], name="send"),
    Route("/verify/{signature:str}", endpoint=verify, methods=["GET"], name="verify"),
    Mount(
        "/static",
        app=StaticFiles(directory=str(Path(__file__).parent / "static")),
        name="static",
    ),
]
middleware = [
    Middleware(TrustedHostMiddleware, allowed_hosts=settings.TRUSTED_HOSTS),
]
app = Starlette(routes=routes, middleware=middleware, debug=settings.DEBUG)


def run() -> None:
    import uvicorn
    from uvicorn.config import LOGGING_CONFIG

    LOGGING_CONFIG["loggers"]["access-guard"] = {
        "handlers": ["default"],
        "level": "DEBUG" if settings.DEBUG else "INFO",
    }
    uvicorn.run(
        app,
        host=settings.HOST,
        port=settings.PORT,
        proxy_headers=True,
        log_config=LOGGING_CONFIG,
    )
