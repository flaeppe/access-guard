from __future__ import annotations

from http import HTTPStatus

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .. import settings
from ..log import logger
from ..schema import AuthSignature, AuthSignatureExpired
from .cookies import set_verified_cookie


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
        return HTMLResponse(status_code=HTTPStatus.NOT_FOUND)

    response = RedirectResponse(
        url=auth_signature.forward_headers.url_unparsed, status_code=HTTPStatus.FOUND
    )
    signature = settings.SIGNING.timed.dumps({"email": auth_signature.email})
    set_verified_cookie(
        response, value=signature if isinstance(signature, str) else signature.decode()
    )
    logger.info("validate_auth.success")
    return response
