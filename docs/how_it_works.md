The entrypoint path to the Access guard service is `/auth`. This is where a forwarder
should send a request to check if access should be granted or not. This should be _the
only_ path that will have to be considered by a forwarding party.

An Access guard response to a forwarded request with a `2XX` status code means that
_access is granted_ and the original request should be performed. A request resulting in
_any other_ status code, Access guard expects the forwarder to return the response from
Access guard to the client.

When an incoming request on `/auth` could not result in a response granting access (i.e.
result in a `2XX` status code); Access guard looks for the following `X-Forwarded-`
headers to initiate its email verification flow:

| Forward-Request Header | Property          |
| :--------------------- | :---------------- |
| X-Forwarded-Method     | HTTP Method       |
| X-Forwarded-Proto      | Protocol          |
| X-Forwarded-Host       | Host              |
| X-Forwarded-Uri        | Request URI       |
| X-Forwarded-For        | Source IP-Address |

!!! warning

    If any of the `X-Forwarded-` headers in the table above is missing from the request,
    the verification flow will not be initiated and a client will instead be presented
    with a `401` status code response. In other words; all of those headers are
    required.

At the first stage of the email verification flow a client will be asked to enter an
email address, this email address will receive an email containing a "magic link", given
that the email address is accepted by Access guard.

!!! info

    If an email address that is not accepted by Access guard is posted, the client will
    still be shown a "check your inbox" page. Although Access guard __will not__ have
    sent any verification email to such addresses.

When a "magic link" in an email is clicked, Access guard will verify its signature. And
if successful, redirect the client to the destination that can be assembled from the
`X-Forwarded-` headers that were sent by the forwarder on the request that initiated
the verification flow. Access guard also attaches a cookie to this redirect, granting
future requests access for a limited amount of time. Given that the value of the cookie
has not been tampered with.
