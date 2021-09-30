from __future__ import annotations

import logging
from http import HTTPStatus
from pathlib import Path
from typing import Any, Awaitable, Callable

from itsdangerous.exc import BadData, SignatureExpired
from pydantic.error_wrappers import ValidationError
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from . import settings
from .emails import send_mail
from .forms import SendEmailForm, VerificationForm
from .schema import (
    ForwardHeaders,
    InvalidForwardHeader,
    LoginSignature,
    MissingForwardHeader,
    PartialSignature,
)

logging.basicConfig(level=(logging.DEBUG if settings.DEBUG else logging.INFO))
logger = logging.getLogger(__name__)


LOGIN_COOKIE_KEY = "access-guard-forwarded"
VERIFIED_COOKIE_KEY = "access-guard-session"

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


class TamperedLoginCookie(Exception):
    ...


def validate_login_cookie(request: Request) -> ForwardHeaders | None:
    cookie = request.cookies.get(LOGIN_COOKIE_KEY)
    try:
        return ForwardHeaders.decode(cookie) if cookie else None
    except SignatureExpired as exc:
        # We'll simulate an expired cookie signature as an expired cookie
        # thus allowing for generating a new one
        date_signed = exc.date_signed.isoformat() if exc.date_signed else "--"
        logger.info(
            "parse_login_cookie.signature_expired %s", date_signed, exc_info=True
        )
        return None
    except BadData as exc:
        raise TamperedLoginCookie from exc


Endpoint = Callable[[Request], Awaitable[Response]]


def check_if_verified(endpoint: Endpoint) -> Endpoint:
    async def check(request: Request) -> Response:
        cookie = request.cookies.get(VERIFIED_COOKIE_KEY, "")
        is_verified = False
        try:
            is_verified = bool(cookie) and bool(
                settings.SIGNING.timed.loads(
                    cookie, max_age=settings.VERIFY_SIGNATURE_MAX_AGE
                )
            )
        except SignatureExpired:
            logger.debug("verify_session.signature_expired", exc_info=True)
        except BadData:
            logger.warning("verify_session.bad_data", exc_info=True)

        if is_verified:
            # TODO: Verify payload with settings.EMAIL_PATTERNS
            response = HTMLResponse("", status_code=HTTPStatus.OK)
            if request.cookies.get(LOGIN_COOKIE_KEY):
                response.delete_cookie(LOGIN_COOKIE_KEY, domain=settings.COOKIE_DOMAIN)
            logger.debug("verify_session.success")
            return response

        return await endpoint(request)

    return check


async def prepare_email_auth(request: Request) -> Response:
    if not validate_login_cookie(request):
        forward_headers = ForwardHeaders.parse(request.headers)
        response = RedirectResponse(
            # TODO: Take protocol from forward headers
            url=f"http://{settings.DOMAIN}/auth",
            # TODO: Don't redirect POST (data)
            status_code=HTTPStatus.TEMPORARY_REDIRECT,
        )
        response.set_cookie(
            key=LOGIN_COOKIE_KEY,
            value=forward_headers.encode(),
            max_age=settings.LOGIN_COOKIE_MAX_AGE,
            expires=settings.LOGIN_COOKIE_MAX_AGE,
            domain=settings.COOKIE_DOMAIN,
            secure=False,  # TODO: app.state.config.cookie_secure
            httponly=True,
        )
        return response

    # Refreshing at certain points could result in domain we're currently at not
    # being our auth host and now we have a valid login cookie. If that is the case,
    # we redirect to our auth host, revisiting this place under configured domain.
    # As otherwise any form we render could post towards somewhere that'll 404.
    if request.base_url.netloc != settings.DOMAIN:
        return RedirectResponse(
            # TODO: Take protocol from forward headers
            url=f"http://{settings.DOMAIN}/auth",
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

        login_signature = LoginSignature.create(
            email=form.email,
            valid_code=form.matches_patterns(settings.EMAIL_PATTERNS),
        )
        email_task = None
        if login_signature.has_valid_code:
            email_task = BackgroundTask(send_mail, signature=login_signature)
            logger.debug("auth.send_verification_email")

        return RedirectResponse(
            url=request.url_for(
                "verify", partial_signature=login_signature.partial.url_encode()
            ),
            status_code=HTTPStatus.SEE_OTHER,
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
        response.delete_cookie(LOGIN_COOKIE_KEY, domain=settings.COOKIE_DOMAIN)
        logger.warning("auth.login_cookie.tampered")
    except (MissingForwardHeader, InvalidForwardHeader):
        response = HTMLResponse("", status_code=HTTPStatus.UNAUTHORIZED)
        response.delete_cookie(LOGIN_COOKIE_KEY, domain=settings.COOKIE_DOMAIN)
        logger.warning("auth.forward_headers.invalid", exc_info=True)

    # Remove any non valid verification cookie when running flow to generate a new one
    if request.cookies.get(VERIFIED_COOKIE_KEY):
        response.delete_cookie(VERIFIED_COOKIE_KEY, domain=settings.COOKIE_DOMAIN)
    return response


@check_if_verified
async def verify(request: Request) -> Response:
    try:
        partial_signature = PartialSignature.url_decode(
            request.path_params["partial_signature"]
        )
    except ValidationError:
        logger.debug("verify.path_params.invalid", exc_info=True)
        return HTMLResponse("", status_code=HTTPStatus.NOT_FOUND)

    forward_headers = None
    try:
        forward_headers = validate_login_cookie(request)
    except TamperedLoginCookie:
        response: Response = HTMLResponse("", status_code=HTTPStatus.UNAUTHORIZED)
        response.delete_cookie(LOGIN_COOKIE_KEY, domain=settings.COOKIE_DOMAIN)
        logger.debug("verify.login_cookie.tampered", exc_info=True)
        return response

    if not forward_headers:
        response = RedirectResponse(
            url=request.url_for("auth"), status_code=HTTPStatus.SEE_OTHER
        )
        # No valid login cookie and no valid verification cookie at verify, then we drop
        # cookies and try to restart from auth
        response.delete_cookie(LOGIN_COOKIE_KEY, domain=settings.COOKIE_DOMAIN)
        response.delete_cookie(VERIFIED_COOKIE_KEY, domain=settings.COOKIE_DOMAIN)
        logger.debug("verify.login_cookie.invalid")
        return response

    data = await request.form() if request.method == "POST" else request.query_params
    try:
        form = VerificationForm.parse_obj({**data, **partial_signature.serialize()})
    except ValidationError as exc:
        context: dict[str, Any] = {
            "request": request,
            "partial_signature": partial_signature,
        }
        if data:  # Avoid rendering errors when no data was sent
            context["errors"] = exc.errors()
        return templates.TemplateResponse(
            "verify.html", context, status_code=HTTPStatus.BAD_REQUEST
        )

    # TODO: Verify email against pattern again
    response = RedirectResponse(
        url=forward_headers.url_unparsed,
        status_code=HTTPStatus.FOUND,
    )
    response.delete_cookie(LOGIN_COOKIE_KEY, domain=settings.COOKIE_DOMAIN)
    value = settings.SIGNING.timed.dumps({"email": form.email})
    assert isinstance(value, str)
    response.set_cookie(
        key=VERIFIED_COOKIE_KEY,
        value=value,
        max_age=settings.VERIFY_SIGNATURE_MAX_AGE,
        expires=settings.VERIFY_SIGNATURE_MAX_AGE,
        domain=settings.COOKIE_DOMAIN,
        secure=False,  # TODO: app.state.config.cookie_secure
        httponly=True,
    )

    return response


routes = [
    Route("/auth", endpoint=auth, methods=["GET", "POST"], name="auth"),
    Route(
        "/verify/{partial_signature:str}",
        endpoint=verify,
        methods=["GET", "POST"],
        name="verify",
    ),
]
app = Starlette(routes=routes, debug=settings.DEBUG)


def run() -> None:
    import uvicorn

    uvicorn.run(app, host=settings.HOST, port=settings.PORT, proxy_headers=True)
