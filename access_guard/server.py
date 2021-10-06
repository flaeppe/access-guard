from __future__ import annotations

from http import HTTPStatus
from pathlib import Path
from typing import Awaitable, Callable

from itsdangerous.exc import BadData, SignatureExpired
from pydantic.error_wrappers import ValidationError
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from . import settings
from .emails import send_mail
from .forms import SendEmailForm
from .log import logger
from .schema import ForwardHeaders, LoginSignature, Verification

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


class TamperedLoginCookie(Exception):
    ...


def validate_login_cookie(request: Request) -> ForwardHeaders | None:
    cookie = request.cookies.get(settings.LOGIN_COOKIE_NAME)
    try:
        return ForwardHeaders.decode(cookie) if cookie else None
    except SignatureExpired as exc:
        # We'll simulate an expired cookie signature as an expired cookie
        # thus allowing for generating a new one
        date_signed = exc.date_signed.isoformat() if exc.date_signed else "--"
        logger.info(
            "validate_login_cookie.signature_expired %s", date_signed, exc_info=True
        )
        return None
    except BadData as exc:
        raise TamperedLoginCookie from exc


Endpoint = Callable[[Request], Awaitable[Response]]


def check_if_verified(endpoint: Endpoint) -> Endpoint:
    async def check(request: Request) -> Response:
        if Verification.check(request.cookies.get(settings.VERIFIED_COOKIE_NAME, "")):
            response = HTMLResponse("", status_code=HTTPStatus.OK)
            if request.cookies.get(settings.LOGIN_COOKIE_NAME):
                response.delete_cookie(
                    settings.LOGIN_COOKIE_NAME, domain=settings.COOKIE_DOMAIN
                )
            logger.info("verify_session.success")
            return response

        return await endpoint(request)

    return check


async def prepare_email_auth(request: Request) -> Response:
    forward_headers = validate_login_cookie(request)
    if not forward_headers:
        forward_headers = ForwardHeaders.parse_obj(request.headers)
        response = RedirectResponse(
            url=f"{forward_headers.proto}://{settings.DOMAIN}/auth",
            status_code=HTTPStatus.SEE_OTHER,
        )
        response.set_cookie(
            key=settings.LOGIN_COOKIE_NAME,
            value=forward_headers.encode(),
            max_age=settings.LOGIN_COOKIE_MAX_AGE,
            expires=settings.LOGIN_COOKIE_MAX_AGE,
            domain=settings.COOKIE_DOMAIN,
            secure=settings.COOKIE_SECURE,
            httponly=True,
        )
        return response

    # Refreshing at certain points could result in domain we're currently at not
    # being our auth host and now we have a valid login cookie. If that is the case,
    # we redirect to our auth host, revisiting this place under configured domain.
    # As otherwise any form we render could post towards somewhere that'll 404.
    if request.base_url.netloc != settings.DOMAIN:
        return RedirectResponse(
            url=f"{forward_headers.proto}://{settings.DOMAIN}/auth",
            status_code=HTTPStatus.TEMPORARY_REDIRECT,
        )
    elif request.method == "POST":
        data = await request.form()
        try:
            form = SendEmailForm.parse_obj(data)
        except ValidationError as exc:
            logger.debug("auth.send_email_form.invalid", exc_info=True)
            return templates.TemplateResponse(
                "send_email.html",
                {"request": request, "errors": exc.errors()},
                status_code=HTTPStatus.BAD_REQUEST,
            )

        email_task = None
        if form.has_allowed_email:
            login_signature = LoginSignature.create(email=form.email)
            email_task = BackgroundTask(
                send_mail,
                email=login_signature.email,
                link=request.url_for("verify", signature=login_signature.signature),
            )
            logger.debug("auth.send_verification_email")

        return templates.TemplateResponse(
            "email_sent.html",
            {"request": request},
            status_code=HTTPStatus.OK,
            # TODO: Starlette is missing an `Optional` as default value is None
            background=email_task,  # type: ignore[arg-type]
        )
    else:
        # Login cookie valid and set, refreshing a page should not allow
        # for being authorized
        return templates.TemplateResponse(
            "send_email.html", {"request": request}, status_code=HTTPStatus.UNAUTHORIZED
        )


@check_if_verified
async def auth(request: Request) -> Response:
    # TODO: Accept verification/authorization from forwarder
    try:
        response = await prepare_email_auth(request)
    except TamperedLoginCookie:
        response = HTMLResponse("", status_code=HTTPStatus.UNAUTHORIZED)
        response.delete_cookie(
            settings.LOGIN_COOKIE_NAME, domain=settings.COOKIE_DOMAIN
        )
        logger.warning("auth.login_cookie.tampered")
    except ValidationError:
        response = HTMLResponse("", status_code=HTTPStatus.UNAUTHORIZED)
        response.delete_cookie(
            settings.LOGIN_COOKIE_NAME, domain=settings.COOKIE_DOMAIN
        )
        logger.warning("auth.invalid", exc_info=True)

    # Remove any non valid verification cookie when running flow to generate a new one
    if request.cookies.get(settings.VERIFIED_COOKIE_NAME):
        response.delete_cookie(
            settings.VERIFIED_COOKIE_NAME, domain=settings.COOKIE_DOMAIN
        )
    return response


@check_if_verified
async def verify(request: Request) -> Response:
    forward_headers = None
    try:
        forward_headers = validate_login_cookie(request)
    except TamperedLoginCookie:
        response: Response = HTMLResponse("", status_code=HTTPStatus.UNAUTHORIZED)
        response.delete_cookie(
            settings.LOGIN_COOKIE_NAME, domain=settings.COOKIE_DOMAIN
        )
        logger.debug("verify.login_cookie.tampered", exc_info=True)
        return response

    if not forward_headers:
        response = RedirectResponse(
            url=request.url_for("auth"), status_code=HTTPStatus.SEE_OTHER
        )
        # No valid login cookie and no valid verification cookie at verify, then we drop
        # cookies and try to restart from auth
        response.delete_cookie(
            settings.LOGIN_COOKIE_NAME, domain=settings.COOKIE_DOMAIN
        )
        response.delete_cookie(
            settings.VERIFIED_COOKIE_NAME, domain=settings.COOKIE_DOMAIN
        )
        logger.debug("verify.login_cookie.invalid")
        return response

    login_signature = LoginSignature.loads(request.path_params["signature"])
    if not login_signature:
        logger.debug("verify.login_signature.invalid")
        return HTMLResponse("", status_code=HTTPStatus.NOT_FOUND)

    response = RedirectResponse(
        url=forward_headers.url_unparsed, status_code=HTTPStatus.FOUND
    )
    response.delete_cookie(settings.LOGIN_COOKIE_NAME, domain=settings.COOKIE_DOMAIN)
    value = settings.SIGNING.timed.dumps({"email": login_signature.email})
    assert isinstance(value, str)
    response.set_cookie(
        key=settings.VERIFIED_COOKIE_NAME,
        value=value,
        max_age=settings.VERIFY_SIGNATURE_MAX_AGE,
        expires=settings.VERIFY_SIGNATURE_MAX_AGE,
        domain=settings.COOKIE_DOMAIN,
        secure=settings.COOKIE_SECURE,
        httponly=True,
    )
    logger.info("verify.success")
    return response


routes = [
    Route("/auth", endpoint=auth, methods=["GET", "POST"], name="auth"),
    Route("/verify/{signature:str}", endpoint=verify, methods=["GET"], name="verify"),
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
