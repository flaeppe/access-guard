!!! info

    The entrypoint path to the Access guard service is `/auth`. This is where a forwarder
    should send a request to check if access should be granted or not.

## Prerequisites

An SMTP server that Access guard can configure its SMTP client to send verification
emails to.

## Command line arguments

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
  -sf PATH_TO_FILE, --secret-file PATH_TO_FILE
                        Secret key file
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
  --email-password-file PATH_TO_FILE
                        File containing password to login with on configured SMTP server [default: unset]
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

## Arguments reference

### Required arguments

#### Email patterns

:   `EMAIL_PATTERN [EMAIL_PATTERN ...]`

    Positional argument

    Email address patterns to match for being allowed possibility to verify and access.
    All entered patterns are case insensitively matched with emails entered by a client.

    ???+ example

        ```console
        *@email.com someone@else.com
        ```

#### Secret

:   `-s/--secret SECRET`

    Should be set to a unique, unpredictable value. Is used for cryptographic signing.

    ???+ warning

        Both `--secret` and `--secret-file` can _not_ be passed at the same time

#### Secret file

:   `-sf/--secret-file PATH_TO_FILE`

    As an alternative to passing the secret via command line, the value can be loaded
    from a file present in the container.

    ???+ example

        ```console
        --secret-file /run/secrets/access-guard-secret
        ```

    Only the _first line_ of the secret file will be read and any newline character at
    the end of it will be removed.

    ???+ warning

        If the first line is _empty_ after any newline character has been removed, an error will be raised.

    ???+ warning

        Both `--secret-file` and `--secret` can _not_ be passed at the same time.

#### Access guard's host

:   `-a/--auth-host AUTH_HOST`

    The configured domain name for the access guard service, without protocol or path. The service
    wants to know this to redirect unverified clients in to the verification flow.

    ???+ example

        ```console
        --auth-host auth.localhost.com
        ```

#### Trusted hosts

:   `-t/--trusted-hosts TRUSTED_HOST [TRUSTED_HOST ...]`

    Hosts/domain names that access guard should serve. Matched against a request's `Host` header.
    Wildcard domains are supported for matching subdomains. Remember that for usage with docker
    and traefik, the _name_ of the access guard service could be a trusted host. That'll allow
    the `forwardauth` middleware to configure an address resolved via a docker network.
    For example (via label/docker configuration):

    ```
    traefik.http.middlewares.access-guard.forwardauth.address: "http://access-guard:8585/auth"
    ```

    ???+ example

        === "Multiple hosts"

            ```console
            --trusted-hosts access-guard auth.localhost.com
            ```
        === "Wildcard subdomains"

            ```console
            --trusted-hosts *.localhost.com
            ```

        === "Any hostname"

            ```console
            --trusted-hosts *
            ```

#### Cookie domain

:   `-c/--cookie-domain COOKIE_DOMAIN`

    The domain to use for cookies. Ensure this value covers the domain set for
    `--auth-host`.

    With an auth host configuration of:

    ```console
    --auth-host auth.localhost.com
    ```

    We can set a cookie domain configuration like

    ```console
    --cookie-domain localhost.com
    ```

    That'll allow a verification cookie to follow along to, for example, the hosts:

    ```
    service_1.localhost.com
    service_2.localhost.com
    ```

#### SMTP host

:   `--email-host EMAIL_HOST`

    The host to use for sending of emails

    ???+ example

        ```console
        --email-host 172.18.0.1
        ```

#### SMTP port

:   `--email-port EMAIL_PORT`

    Port to use for the SMTP server defined in `--email-host`

    ???+ example

        ```console
        --email-port 25
        ```

#### Sender's email address

:   `--from-email FROM_EMAIL`

    What will become the sender's address in sent emails.

    ???+ example

        ```console
        --from-email verificator@email.com
        ```

### Example using minimal arguments

```bash
docker run --rm ghcr.io/flaeppe/access-guard:latest \
  ".*@test.com" \
  --secret supersecret \
  --auth-host access-guard.localhost.com \
  --trusted-hosts access-guard access-guard.localhost.com \
  --cookie-domain localhost.com \
  --email-host mailhog \
  --email-port 1025 \
  --from-email access-guard@local.com
```

### Optional arguments

#### Bind host

:   `--host HOST`

    The socket that access guard's server should bind to. This will be _inside_ of a
    running container.

    ???+ info "Default value"

        0.0.0.0

#### Bind port

:   `--port PORT`

    The port that access guard's server should bind to. This will be _inside_ of a
    running container.

    ???+ info "Default value"

        8585

#### SMTP client username

:   `--email-username EMAIL_USERNAME`

    Username to login with on configured SMTP server

    ???+ info "Default value"

        Not set

#### SMTP client password

:   `--email-password EMAIL_PASSWORD`

    Password to login with on configured SMTP server

    ???+ info "Default value"

        Not set

    ???+ warning

        Both `--email-password` and `--email-password-file` can _not_ be passed at the same
        time

#### SMTP client password file

:   `--email-password-file PATH_TO_FILE`

    As an alternative to passing a password via command line, the value can be loaded
    from a file present in the container.

    Only the _first line_ of the password file will be read and any newline character at
    the end of it will be removed.

    ???+ example

        ```console
        --email-password-file /run/secrets/email-passwd
        ```

    ???+ info "Default value"

        Not set

    ???+ warning

        If the first line is _empty_ after any newline character has been removed, an
        error will be raised.

    ???+ warning

        Both `--email-password-file` and `--email-password` can _not_ be passed at the
        same time

#### SMTP client use TLS

:   `--email-use-tls`

    Make the _initial_ connection to the SMTP server over TLS/SSL.

    ???+ example

        ```console
        --email-use-tls
        ```

    ???+ info "Default value"

        false

    ???+ warning

        Both `--email-use-tls` and `--email-start-tls` can _not_ be passed at the same
        time

#### SMTP client start TLS

:   `--email-start-tls`

    Make the initial connection to the SMTP server over plaintext, and then upgrade the
    connection to TLS/SSL.

    ???+ example

        ```console
        --email-start-tls
        ```

    ???+ info "Default value"

        false

    ???+ warning

        Both `--email-start-tls` and `--email-use-tls` can _not_ be passed at the same time

#### Disable SMTP cert validation

:   `--email-no-validate-certs`

    Disable validating server certificates for SMTP

    ???+ example

        ```console
        --email-no-validate-certs
        ```

    ???+ info "Default value"

        false

#### SMTP client TLS cert

:   `--email-client-cert EMAIL_CLIENT_CERT`

    Path to client side certificate, for TLS verification

    ???+ example

        ```console
        --email-client-cert /path/to/cert
        ```

    ???+ info "Default value"

        Not set

#### SMTP client TLS key

:   `--email-client-key EMAIL_CLIENT_KEY`

    Path to client side key, for TLS verification

    ???+ example

        ```console
        --email-client-key /path/to/key
        ```

    ???+ info "Default value"

        Not set

#### Email subject

:   `--email-subject EMAIL_SUBJECT`

    Subject of the email sent for verification

    ???+ example

        ```console
        --email-subject "Custom email subject line"
        ```

    ???+ info "Default value"

        "Access guard verification"

#### Cookie secure

:   `--cookie-secure`

    Whether to only use secure cookies. When passed, cookies will be marked as 'secure'

    ???+ example

        ```console
        --cookie-secure
        ```

    ???+ info "Default value"

        false

#### Auth cookie name

:   `--auth-cookie-name AUTH_COOKIE_NAME`

    Name for cookie used during auth flow

    ???+ example

        ```console
        --auth-cookie-name cookie-name
        ```

    ???+ info "Default value"

        access-guard-forwarded

#### Verified cookie name

:   `--verified-cookie-name VERIFIED_COOKIE_NAME`

    Name for cookie set when auth completed successfully

    ???+ example

        ```console
        --verified-cookie-name cookie-name
        ```

    ???+ info "Default value"

        access-guard-session

#### Auth cookie max age

:   `--auth-cookie-max-age AUTH_COOKIE_MAX_AGE`

    Seconds before the cookie set _during_ auth flow should expire

    ???+ example

        ```console
        --auth-cookie-max-age 600
        ```

    ???+ info "Default value"

        3600 (1 hour)

#### Verification email max age

:   `--auth-signature-max-age AUTH_SIGNATURE_MAX_AGE`

    Decides how many seconds a verification email should be valid. When the amount of
    seconds has passed, the client has to request a new email.

    ???+ example

        ```console
        --auth-signature-max-age 300
        ```

    ???+ info "Default value"

        600 (10 minutes)

#### Verified session max age

:   `--verify-signature-max-age VERIFY_SIGNATURE_MAX_AGE`

    Decides how many seconds a verified session cookie should be valid. When the amount
    of seconds has passed, the client has to verify again.

    ???+ example

        ```console
        --verify-signature-max-age 43200
        ```

    ???+ info "Default value"

        86400 (24 hours)

### Example using all arguments

```sh
docker run --rm ghcr.io/flaeppe/access-guard:latest \
  ".*@test.com" \
  --secret supersecret \
  --auth-host access-guard.localhost.com \
  --trusted-hosts access-guard access-guard.localhost.com \
  --cookie-domain localhost.com \
  --email-host mailhog \
  --email-port 1025 \
  --from-email access-guard@local.com \
  --host 0.0.0.0 \
  --port 8585 \
  --email-username email-login \
  --email-password SecreT \
  --email-use-tls \
  --email-no-validate-certs \
  --email-client-cert /run/secret/smtp-cert \
  --email-client-key /run/secret/smtp-key \
  --email-subject "You need to verify yourself" \
  --cookie-secure \
  --auth-cookie-name local-access-guard-forwarded \
  --verified-cookie-name local-access-guard-session \
  --auth-cookie-max-age 3600 \
  --auth-signature-max-age 600 \
  --verify-signature-max-age 43200
```

!!! note

    All available arguments aren't included above, since some of them are mutually
    exclusive. In addition to the ones seen above the following arguments also exists:

    - [--secret-file](reference.md#secret-file)
    - [--email-password-file](reference.md#smtp-client-password-file)
    - [--email-start-tls](reference.md#smtp-client-start-tls)
