from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from http import HTTPStatus
from typing import Any, ClassVar

from pydantic.error_wrappers import ValidationError
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response

from .. import csrf, settings
from ..emails import send_mail
from ..forms import SendEmailForm
from ..log import logger
from ..schema import AuthSignature, ForwardHeaders
from ..templating import templates
from .cookies import (
    IncompatibleAuthCookie,
    TamperedAuthCookie,
    set_csrf_cookie,
    validate_auth_cookie,
)


async def send(request: Request) -> Response:
    # Reaching send an auth cookie has to be set
    try:
        forward_headers = validate_auth_cookie(request)
    except (TamperedAuthCookie, IncompatibleAuthCookie):
        response: Response = HTMLResponse(status_code=HTTPStatus.UNAUTHORIZED)
        response.delete_cookie(settings.AUTH_COOKIE_NAME, domain=settings.COOKIE_DOMAIN)
        return response

    if not forward_headers:
        logger.warning("send.auth_cookie.missing")
        return HTMLResponse(status_code=HTTPStatus.UNAUTHORIZED)

    # Should only raise if access-guard has been configured incorrectly
    assert request.base_url.netloc == settings.DOMAIN
    return (
        await _handle_send_email(request, forward_headers)
        if request.method == "POST"
        else SendEmailResponse(
            request=request, host_name=forward_headers.host_name
        ).prepare()
    )


async def _handle_send_email(
    request: Request, forward_headers: ForwardHeaders
) -> Response:
    data = await request.form()
    try:
        form = SendEmailForm.parse_obj(data)
    except ValidationError as exc:
        logger.debug("handle_send_email.form.invalid", exc_info=True)
        return SendEmailResponse(
            request=request, host_name=forward_headers.host_name, errors=exc.errors()
        ).prepare()

    if not csrf.does_token_match(
        form.csrf_token, request.cookies.get(csrf.CSRF_COOKIE_NAME, "")
    ):
        logger.warning("handle_send_email.csrf.invalid")
        return HTMLResponse(status_code=HTTPStatus.FORBIDDEN)

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
        logger.debug("handle_send_email.send_verification_email")

    response = templates.TemplateResponse(
        "email_sent.html",
        {"request": request},
        status_code=HTTPStatus.OK,
        # TODO: Starlette is missing an `Optional` as default value is None
        background=email_task,  # type: ignore[arg-type]
    )
    response.delete_cookie(settings.AUTH_COOKIE_NAME, domain=settings.COOKIE_DOMAIN)
    response.delete_cookie(csrf.CSRF_COOKIE_NAME, domain=settings.COOKIE_DOMAIN)
    return response


@dataclass(frozen=True)
class SendEmailResponse:
    request: Request
    host_name: str
    errors: list[dict[str, Any]] | None = None

    template: ClassVar[str] = "send_email.html"

    @cached_property
    def csrf_pair(self) -> tuple[str, str]:
        return csrf.get_token()

    @property
    def csrf_token(self) -> str:
        return self.csrf_pair[0]

    @property
    def csrf_cookie_value(self) -> str:
        return self.csrf_pair[1]

    @property
    def context(self) -> dict[str, Any]:
        ctx = {
            "request": self.request,
            "host_name": self.host_name,
            "csrf_token": self.csrf_token,
        }
        if self.errors:
            ctx["errors"] = self.errors
        return ctx

    def prepare(self) -> Response:
        response = templates.TemplateResponse(
            self.template,
            self.context,
            status_code=HTTPStatus.OK if not self.errors else HTTPStatus.BAD_REQUEST,
        )
        set_csrf_cookie(response, value=self.csrf_cookie_value)
        return response