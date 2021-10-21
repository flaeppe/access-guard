from __future__ import annotations

from http import HTTPStatus

from pydantic.error_wrappers import ValidationError
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .. import settings
from ..log import logger
from ..schema import ForwardHeaders, Verification
from .cookies import (
    IncompatibleAuthCookie,
    TamperedAuthCookie,
    set_auth_cookie,
    validate_auth_cookie,
)


async def auth(request: Request) -> Response:
    # TODO: Accept verification/authorization from forwarder
    # First check if the request has a valid session
    session_value = request.cookies.get(settings.VERIFIED_COOKIE_NAME, "")
    if Verification.check(session_value):
        response: Response = HTMLResponse(status_code=HTTPStatus.OK)
        if request.cookies.get(settings.AUTH_COOKIE_NAME):
            response.delete_cookie(
                settings.AUTH_COOKIE_NAME, domain=settings.COOKIE_DOMAIN
            )
        logger.info("auth.access_granted")
        return response

    # If there's no valid session, attempt to collect forward headers and start
    # verification flow
    response = (
        start_verification_response(forward_headers=forward_headers)
        if (forward_headers := get_forward_headers(request))
        else missing_forward_headers_response(
            drop_auth_cookie=bool(request.cookies.get(settings.AUTH_COOKIE_NAME))
        )
    )
    # Remove any non valid verification cookie when running flow to generate a new one
    if session_value:
        response.delete_cookie(
            settings.VERIFIED_COOKIE_NAME, domain=settings.COOKIE_DOMAIN
        )
    return response


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


def start_verification_response(forward_headers: ForwardHeaders) -> RedirectResponse:
    response = RedirectResponse(
        url=f"{forward_headers.proto}://{settings.DOMAIN}/send",
        status_code=HTTPStatus.SEE_OTHER,
    )
    set_auth_cookie(response, value=forward_headers.encode())
    return response


def missing_forward_headers_response(drop_auth_cookie: bool) -> HTMLResponse:
    response = HTMLResponse(status_code=HTTPStatus.UNAUTHORIZED)
    if drop_auth_cookie:
        response.delete_cookie(settings.AUTH_COOKIE_NAME, domain=settings.COOKIE_DOMAIN)
    return response
