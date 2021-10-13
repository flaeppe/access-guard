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
  --email-validate-certs
                        Validate server certificates for SMTP [default: true]
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
  and traefik, the _name_ of the access guard service should be a trusted host.

  Examples:

  ```
  --trusted-hosts access-guard auth.localhost.com
  ```

  To allow multiple subdomains:

  ```
  --trusted-hosts *.localhost.com
  ```

  To allow any hostname use:

  ```
  --trusted-hosts *
  ```

- `-c/--cookie-domain COOKIE_DOMAIN`

  The domain to use for cookies. Ensure this value covers domain set for `--auth-host`

- `--email-host EMAIL_HOST`

  The host to use for sending of emails

- `--email-port EMAIL_PORT`

  Port to use for the SMTP server defined in `--email-host`

- `--from-email FROM_EMAIL`

  What will become the sender's address in sent emails.

#### Optional arguments:

- `--host HOST`
- `--port PORT`
- `--email-username EMAIL_USERNAME`
- `--email-password EMAIL_PASSWORD`
- `--email-use-tls`
- `--email-start-tls`
- `--email-validate-certs`
- `--email-client-cert EMAIL_CLIENT_CERT`
- `--email-client-key EMAIL_CLIENT_KEY`
- `--email-subject EMAIL_SUBJECT`
- `--cookie-secure`
- `--auth-cookie-name AUTH_COOKIE_NAME`
- `--verified-cookie-name VERIFIED_COOKIE_NAME`
- `--auth-cookie-max-age AUTH_COOKIE_MAX_AGE`
- `--auth-signature-max-age AUTH_SIGNATURE_MAX_AGE`
- `--verify-signature-max-age VERIFY_SIGNATURE_MAX_AGE`

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
