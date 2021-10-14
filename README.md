# Access Guard [![CI](https://github.com/flaeppe/access-guard/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/flaeppe/access-guard/actions/workflows/ci.yml)

A forward authentication service that provides email verification.

## Contents

- [Prerequisites](#prerequisites)
- [Usage](#usage)
  - [traefik](#traefik)
  - [Command line arguments](#command-line-arguments)
  - [Arguments reference](#arguments-reference)
    - [Required arguments](#required-arguments)
    - [Optional arguments](#optional-arguments)
- [Bleeding edge image](#bleeding-edge-image)
- [Contributing](#contributing)
  - [Build image](#build-image)
  - [Running tests](#running-tests)
  - [Linting](#linting)
  - [Static typing](#static-typing)
  - [Coverage](#coverage)
  - [Upgrade/change requirements](#upgradechange-requirements)

## Prerequisites

You will need an SMTP server that Access guard can configure its SMTP client
to send its verification emails.

## Usage

### traefik

View [docker-compose.yml](https://github.com/flaeppe/access-guard/blob/master/docker-compose.yml)
to see a configuration example with [traefik's forward auth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)

### Command line arguments

```console
$ docker run --rm ghcr.io/flaeppe/access-guard:latest --help
usage: access-guard [-h] -s SECRET -a AUTH_HOST -t TRUSTED_HOST [TRUSTED_HOST ...] -c COOKIE_DOMAIN [-V] [-d] [--host HOST] [--port PORT] --email-host EMAIL_HOST --email-port EMAIL_PORT --from-email FROM_EMAIL [--email-username EMAIL_USERNAME]
                    [--email-password EMAIL_PASSWORD] [--email-use-tls | --email-start-tls] [--email-validate-certs] [--email-client-cert EMAIL_CLIENT_CERT] [--email-client-key EMAIL_CLIENT_KEY] [--email-subject EMAIL_SUBJECT] [--cookie-secure]
                    [--auth-cookie-name AUTH_COOKIE_NAME] [--verified-cookie-name VERIFIED_COOKIE_NAME] [--auth-cookie-max-age AUTH_COOKIE_MAX_AGE] [--auth-signature-max-age AUTH_SIGNATURE_MAX_AGE] [--verify-signature-max-age VERIFY_SIGNATURE_MAX_AGE]
                    EMAIL_PATTERN [EMAIL_PATTERN ...]

...

positional arguments:
  EMAIL_PATTERN         Email addresses to match, each compiled to a regex

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -d, --debug
  --host HOST           Server host. [default: 0.0.0.0]
  --port PORT           Server port. [default: 8585]

Required arguments:
  -s SECRET, --secret SECRET
                        Secret key
  -a AUTH_HOST, --auth-host AUTH_HOST
                        The entrypoint domain name for access guard (without protocol or path)
  -t TRUSTED_HOST [TRUSTED_HOST ...], --trusted-hosts TRUSTED_HOST [TRUSTED_HOST ...]
                        Hosts/domain names that access guard should serve. Matched against a request's Host header. Wildcard domains such as '*.example.com' are supported for matching subdomains. To allow any hostname use: *
  -c COOKIE_DOMAIN, --cookie-domain COOKIE_DOMAIN
                        The domain to use for cookies. Ensure this value covers domain set for AUTH_HOST

Required email arguments:
  SMTP/Email specific configuration

  --email-host EMAIL_HOST
                        The host to use for sending emails
  --email-port EMAIL_PORT
                        Port to use for the SMTP server defined in --email-host
  --from-email FROM_EMAIL
                        What will become the sender's address in sent emails

Optional email arguments:
  SMTP/Email specific configuration

  --email-username EMAIL_USERNAME
                        Username to login with on configured SMTP server [default: unset]
  --email-password EMAIL_PASSWORD
                        Password to login with on configured SMTP server [default: unset]
  --email-use-tls       Make the _initial_ connection to the SMTP server over TLS/SSL [default: false]
  --email-start-tls     Make the initial connection to the SMTP server over plaintext, and then upgrade the connection to TLS/SSL [default: false]
  --email-no-validate-certs
                        Disable validating server certificates for SMTP [default: false]
  --email-client-cert EMAIL_CLIENT_CERT
                        Path to client side certificate, for TLS verification [default: unset]
  --email-client-key EMAIL_CLIENT_KEY
                        Path to client side key, for TLS verification [default: unset]
  --email-subject EMAIL_SUBJECT
                        Subject of the email sent for verification [default: Access guard verification]

Optional cookie arguments:
  Configuration for cookies

  --cookie-secure       Whether to only use secure cookies. When passed, cookies will be marked as 'secure' [default: false]
  --auth-cookie-name AUTH_COOKIE_NAME
                        Name for cookie used during auth flow [default: access-guard-forwarded]
  --verified-cookie-name VERIFIED_COOKIE_NAME
                        Name for cookie set when auth completed successfully [default: access-guard-session]
  --auth-cookie-max-age AUTH_COOKIE_MAX_AGE
                        Seconds before the cookie set _during_ auth flow should expire [default: 3600 (1 hour)]
  --auth-signature-max-age AUTH_SIGNATURE_MAX_AGE
                        Decides how many seconds a verification email should be valid. When the amount of seconds has passed, the client has to request a new email. [default: 600 (10 minutes)]
  --verify-signature-max-age VERIFY_SIGNATURE_MAX_AGE
                        Decides how many seconds a verified session cookie should be valid. When the amount of seconds has passed, the client has to verify again. [default: 86400 (24 hours)]
```

### Arguments reference

#### Required arguments:

- `EMAIL_PATTERN [EMAIL_PATTERN ...]` (positional)

  Email address patterns to match for being allowed possibility to verify and access.

  All entered patterns are case insensitively matched with emails entered by a client.

  Example:

  ```
  *@email.com someone@else.com
  ```

- `-s/--secret SECRET`

  Should be set to a unique, unpredictable value. Is used for cryptographic signing.

- `-a/--auth-host AUTH_HOST`

  The configured domain name for the access guard service, without protocol or path. The service
  wants to know this to redirect unverified clients in to the verification flow.

  Example:

  ```
  --auth-host auth.localhost.com
  ```

- `-t/--trusted-hosts TRUSTED_HOST [TRUSTED_HOST ...]`

  Hosts/domain names that access guard should serve. Matched against a requests's `Host` header.
  Wildcard domains are supported for matching subdomains. Remember that for usage with docker
  and traefik, the _name_ of the access guard service could be a trusted host. That'll allow
  the `forwardauth` middleware to configure an address resolved via a docker network.
  For example (via label/docker configuration):

  ```
  traefik.http.middlewares.access-guard.forwardauth.address: "http://access-guard:8585/auth"
  ```

  Examples:

  ```
  --trusted-hosts access-guard auth.localhost.com
  ```

  To allow multiple subdomains:

  ```
  --trusted-hosts *.localhost.com
  ```

  To allow any hostname, use:

  ```
  --trusted-hosts *
  ```

- `-c/--cookie-domain COOKIE_DOMAIN`

  The domain to use for cookies. Ensure this value covers domain set for `--auth-host`.

  With an auth host configuration of:

  ```
  --auth-host auth.localhost.com
  ```

  We can set a cookie domain configuration like

  ```
  --cookie-domain localhost.com
  ```

  That'll allow a verification cookie to follow along to protected services like:

  ```
  service_1.localhost.com
  service_2.localhost.com
  ```

- `--email-host EMAIL_HOST`

  The host to use for sending of emails

  Example:

  ```
  --email-host 172.18.0.1
  ```

- `--email-port EMAIL_PORT`

  Port to use for the SMTP server defined in `--email-host`

  Example:

  ```
  --email-port 25
  ```

- `--from-email FROM_EMAIL`

  What will become the sender's address in sent emails.

  ```
  --from-email verificator@email.com
  ```

#### Optional arguments:

- `--host HOST` [default: 0.0.0.0]

  The socket that access guard's server should bind to. This will be _inside_ of a
  running container.

- `--port PORT` [default: 8585]

  The port that access guard's server should bind to. This will be _inside_ of a
  running container.

- `--email-username EMAIL_USERNAME` [default: unset]

  Username to login with on configured SMTP server

- `--email-password EMAIL_PASSWORD` [default: unset]

  Password to login with on configured SMTP server

- `--email-use-tls` [default: false]

  Make the _initial_ connection to the SMTP server over TLS/SSL.
  Both `--email-use-tls` and `--email-start-tls` can _not_ be passed at the same time

- `--email-start-tls` [default: false]

  Make the initial connection to the SMTP server over plaintext, and then upgrade the
  connection to TLS/SSL.
  Both `--email-start-tls` and `--email-use-tls` can _not_ be passed at the same time

- `--email-no-validate-certs` [default: false]

  Disable validating server certificates for SMTP

- `--email-client-cert EMAIL_CLIENT_CERT` [default: unset]

  Path to client side certificate, for TLS verification

- `--email-client-key EMAIL_CLIENT_KEY` [default: unset]

  Path to client side key, for TLS verification

- `--email-subject EMAIL_SUBJECT` [default: Access guard verification]

  Subject of the email sent for verification

- `--cookie-secure` [default: false]

  Whether to only use secure cookies. When passed, cookies will be marked as 'secure'

- `--auth-cookie-name AUTH_COOKIE_NAME` [default: access-guard-forwarded]

  Name for cookie used during auth flow

- `--verified-cookie-name VERIFIED_COOKIE_NAME` [default: access-guard-session]

  Name for cookie set when auth completed successfully

- `--auth-cookie-max-age AUTH_COOKIE_MAX_AGE` [default: 3600 (1 hour)]

  Seconds before the cookie set _during_ auth flow should expire

- `--auth-signature-max-age AUTH_SIGNATURE_MAX_AGE` [default: 600 (10 minutes)]

  Decides how many seconds a verification email should be valid. When the amount of
  seconds has passed, the client has to request a new email.

- `--verify-signature-max-age VERIFY_SIGNATURE_MAX_AGE` [default: 86400 (24 hours)]

  Decides how many seconds a verified session cookie should be valid. When the amount
  of seconds has passed, the client has to verify again.

## Bleeding edge image

An image named `edge` is built and released as soon as code is committed and passed
all automated tests. Expect that there could be immediate issues when running with
this tag.

Use the following to pull the `edge` image from command line:

```sh
$ docker pull ghcr.io/flaeppe/access-guard:edge
```

## Contributing

All contributions are welcome. Here's a few useful shortcuts/hints to get you started

### Build image

```sh
make build
```

### Running tests

Tests are run with `pytest` and the whole suite can be run with the following command

```sh
make test
```

Currently the command is quite naive and will run the whole test suite. Although
it's possible to pass flags to `pytest` via:

```sh
make test test="-k XYZ"
```

### Linting

Install and use [pre-commit](https://pre-commit.com/#installation) for linting files

### Static typing

```sh
make mypy
```

### Coverage

Intention is to keep it at 100%, because, why not.

### Upgrade/change requirements

For updating/changing of requirements, edit an `reqs/*requirement.in` file and run
the following command

```sh
make requirements
```
