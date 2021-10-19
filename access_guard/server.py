from __future__ import annotations

from http import HTTPStatus
from pathlib import Path

from itsdangerous.exc import BadData, SignatureExpired
from pydantic.error_wrappers import ValidationError
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from . import settings
from .emails import send_mail
from .forms import SendEmailForm
from .log import logger
from .schema import AuthSignature, AuthSignatureExpired, ForwardHeaders, Verification
from .templating import templates


class TamperedAuthCookie(Exception):
    ...


class IncompatibleAuthCookie(Exception):
    ...


def validate_auth_cookie(request: Request) -> ForwardHeaders | None:
    cookie = request.cookies.get(settings.AUTH_COOKIE_NAME)
    try:
        return ForwardHeaders.decode(cookie) if cookie else None
    except SignatureExpired as exc:
        # We'll simulate an expired cookie signature as an expired cookie
        # thus allowing for generating a new one
        date_signed = exc.date_signed.isoformat() if exc.date_signed else "--"
        logger.info("validate_auth_cookie.signature_expired %s", date_signed)
        return None
    except BadData as exc:
        logger.warning("validate_auth_cookie.tampered", exc_info=True)
        raise TamperedAuthCookie from exc
    except ValidationError as exc:
        logger.error(
            "validate_auth_cookie.incompatible_signature_payload %s",
            cookie,
            exc_info=True,
        )
        raise IncompatibleAuthCookie from exc


def get_forward_headers(request: Request) -> ForwardHeaders | None:
    # First try to get forward headers from an auth cookie
    try:
        forward_headers = validate_auth_cookie(request)
    except (TamperedAuthCookie, IncompatibleAuthCookie):
        forward_headers = None

    if not forward_headers:
        # If we can't get them from an auth cookie, also try from headers
        try:
            forward_headers = ForwardHeaders.parse_obj(request.headers)
        except ValidationError:
            logger.warning("get_forward_headers.invalid_headers", exc_info=True)

    return forward_headers


async def auth(request: Request) -> Response:
    # TODO: Accept verification/authorization from forwarder
    # First check if the request has a valid session
    if Verification.check(request.cookies.get(settings.VERIFIED_COOKIE_NAME, "")):
        response: Response = HTMLResponse("", status_code=HTTPStatus.OK)
        if request.cookies.get(settings.AUTH_COOKIE_NAME):
            response.delete_cookie(
                settings.AUTH_COOKIE_NAME, domain=settings.COOKIE_DOMAIN
            )
        logger.info("auth.access_granted")
        return response

    # If there's no valid session, collect forward headers if possible and
    # redirect to /send
    if forward_headers := get_forward_headers(request):
        response = RedirectResponse(
            url=f"{forward_headers.proto}://{settings.DOMAIN}/send",
            status_code=HTTPStatus.SEE_OTHER,
        )
        response.set_cookie(
            key=settings.AUTH_COOKIE_NAME,
            value=forward_headers.encode(),
            max_age=settings.AUTH_COOKIE_MAX_AGE,
            expires=settings.AUTH_COOKIE_MAX_AGE,
            domain=settings.COOKIE_DOMAIN,
            secure=settings.COOKIE_SECURE,
            httponly=True,
        )
    else:
        response = HTMLResponse("", status_code=HTTPStatus.UNAUTHORIZED)
        # TODO: Should we even clean up cookies?
        if request.cookies.get(settings.AUTH_COOKIE_NAME):
            response.delete_cookie(
                settings.AUTH_COOKIE_NAME, domain=settings.COOKIE_DOMAIN
            )

    # Remove any non valid verification cookie when running flow to generate a new one
    if request.cookies.get(settings.VERIFIED_COOKIE_NAME):
        response.delete_cookie(
            settings.VERIFIED_COOKIE_NAME, domain=settings.COOKIE_DOMAIN
        )
    return response


async def handle_send_email(
    request: Request, forward_headers: ForwardHeaders
) -> Response:
    data = await request.form()
    try:
        form = SendEmailForm.parse_obj(data)
    except ValidationError as exc:
        logger.debug("auth.send_email_form.invalid", exc_info=True)
        return templates.TemplateResponse(
            "send_email.html",
            {
                "request": request,
                "host_name": forward_headers.host_name,
                "errors": exc.errors(),
            },
            status_code=HTTPStatus.BAD_REQUEST,
        )

    email_task = None
    if form.has_allowed_email:
        auth_signature = AuthSignature.create(
            email=form.email, forward_headers=forward_headers
        )
        email_task = BackgroundTask(
            send_mail,
            email=auth_signature.email,
            link=request.url_for("verify", signature=auth_signature.signature),
            host_name=forward_headers.host_name,
        )
        logger.debug("auth.send_verification_email")

    response = templates.TemplateResponse(
        "email_sent.html",
        {"request": request},
        status_code=HTTPStatus.OK,
        # TODO: Starlette is missing an `Optional` as default value is None
        background=email_task,  # type: ignore[arg-type]
    )
    response.delete_cookie(settings.AUTH_COOKIE_NAME, domain=settings.COOKIE_DOMAIN)
    return response


async def send(request: Request) -> Response:
    # Reaching send an auth cookie has to be set
    try:
        forward_headers = validate_auth_cookie(request)
    except (TamperedAuthCookie, IncompatibleAuthCookie):
        response: Response = HTMLResponse("", status_code=HTTPStatus.UNAUTHORIZED)
        response.delete_cookie(settings.AUTH_COOKIE_NAME, domain=settings.COOKIE_DOMAIN)
        return response

    if not forward_headers:
        logger.warning("send.auth_cookie.missing")
        return HTMLResponse("", status_code=HTTPStatus.UNAUTHORIZED)

    # Should only raise if access-guard has been configured incorrectly
    assert request.base_url.netloc == settings.DOMAIN
    if request.method == "POST":
        # TODO: CSRF
        response = await handle_send_email(request, forward_headers)
    else:
        response = templates.TemplateResponse(
            "send_email.html",
            {"request": request, "host_name": forward_headers.host_name},
            status_code=HTTPStatus.OK,
        )

    return response


async def verify(request: Request) -> Response:
    try:
        auth_signature = AuthSignature.loads(request.path_params["signature"])
    except AuthSignatureExpired:
        # Attempt restarting auth on an expired signature
        logger.debug("verify.auth_signature.expired")
        return RedirectResponse(
            url=request.url_for("auth"), status_code=HTTPStatus.SEE_OTHER
        )

    if not auth_signature:
        logger.debug("verify.auth_signature.invalid")
        return HTMLResponse("", status_code=HTTPStatus.NOT_FOUND)

    response = RedirectResponse(
        url=auth_signature.forward_headers.url_unparsed, status_code=HTTPStatus.FOUND
    )
    value = settings.SIGNING.timed.dumps({"email": auth_signature.email})
    response.set_cookie(
        key=settings.VERIFIED_COOKIE_NAME,
        value=value if isinstance(value, str) else value.decode(),
        max_age=settings.VERIFY_SIGNATURE_MAX_AGE,
        expires=settings.VERIFY_SIGNATURE_MAX_AGE,
        domain=settings.COOKIE_DOMAIN,
        secure=settings.COOKIE_SECURE,
        httponly=True,
    )
    logger.info("validate_auth.success")
    return response


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
