!!! info

    The example here expects that you have [docker](https://docs.docker.com/get-docker/)
    with [compose](https://docs.docker.com/compose/install/) installed on your computer.

This is an example setup with [traefik's forward auth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)
via [docker-compose](https://docs.docker.com/compose/) that should be possible to start
as is, with a slight configuration of a local hosts file pointing the `.localhost.com`
domains to `127.0.0.1`.

```yaml title="docker-compose.yml"
version: "3.8"

services:
  traefik:
    image: traefik:v2.5
    command: |
      --providers.docker
      --providers.docker.exposedByDefault=false
      --log.level=INFO
      --accesslog=true
      --entryPoints.web.address=:80
    ports:
      - "80:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  whoami:
    image: traefik/whoami
    labels:
      traefik.enable: "true"
      traefik.http.routers.whoami.rule: "Host(`whoami.localhost.com`)"
      traefik.http.routers.whoami.middlewares: "access-guard@docker"

  access-guard:
    image: ghcr.io/flaeppe/access-guard
    command: [
      ".*@test\\.com$$",
      "--secret", "supersecret",
      "--auth-host", "access-guard.localhost.com",
      "--trusted-hosts", "access-guard", "access-guard.localhost.com",
      "--cookie-domain", "localhost.com",
      "--email-host", "mailhog",
      "--email-port", "1025",
      "--from-email", "access-guard@local.com"
      ]
    depends_on:
      - mailhog
    labels:
      traefik.enable: "true"
      traefik.http.routers.access-guard.rule: "Host(`access-guard.localhost.com`)"
      traefik.http.routers.access-guard.service: "access-guard"
      traefik.http.middlewares.access-guard.forwardauth.address: "http://access-guard:8585/auth"
      traefik.http.services.access-guard.loadbalancer.server.port: "8585"

  mailhog:
    image: mailhog/mailhog
    ports:
      - "8025:8025"
```

### Configuration walk-through

There are 4 services that will be started from the configuration above:

- __[traefik](https://github.com/traefik/traefik)__

    An HTTP reverse proxy and load balancer, that'll be responsible for routing traffic
    to our services.

- __[whoami](https://github.com/traefik/whoami)__

    A dummy, `whoami`, service that'll act as a service that we want `access-guard` to
    verify authentication for before access is granted.

- __[access-guard](https://github.com/flaeppe/access-guard)__

    The forward auth service, `access-guard`. This is where the `traefik` service will
    delegate authentication to, before granting access to the `whoami` service.

- __[mailhog](https://github.com/mailhog/MailHog)__

    Catchall service for emails, so that `access-guard` can send verification emails
    somewhere.

The following label set on the `access-guard` service defines the entrypoint of the
forward auth. This is where `traefik` will forward requests to see if they're granted
access.

```
traefik.http.middlewares.access-guard.forwardauth.address: "http://access-guard:8585/auth"
```

[Configured email domains](reference.md#email-patterns) are: `.*@test.com` which means
that an email address ending with `@test.com` can receive emails with a verification
link. If an email address is entered that doesn't end with `@test.com`, no email will be
sent.

The `supersecret` [secret](reference.md#secret) value is used for cryptographic signing
of the "magic link" that'll be sent in the email by `access-guard`. Allowing us to
verify that it is indeed `access-guard` that has created the "magic link" and that it
hasn't been tampered with.

The [--auth-host](reference.md#access-guards-host) value is the entrypoint host name for
`access-guard`. This is the host we intend clients to see in a browser's address bar
while verifying.

The [--trusted-hosts](reference.md#trusted-hosts) values are the host values which
`access-guard` should accept incoming traffic from.

The [--cookie-domain](reference.md#cookie-domain) value is what `access-guard` will set
as `domain` value on a cookie.

The [--email-host](reference.md#smtp-host) value is where `access-guard`'s SMTP client
will send emails to.

The [--email-port](reference.md#smtp-port) value is the port of the SMTP server defined
in `--email-host`.

The [--from-email](reference.md#senders-email-address) value is what will become the
sender's address in sent emails.

With this setup, emails will be sent to the catchall service `mailhog` that'll be
accessible at [http://localhost:8025](http://localhost:8025).

### Trying it out

1. Copy the service declaration from above to a `docker-compose.yml` file on your
   computer

2. Add the configured hosts to your local hosts file (e.g. `/etc/hosts`)

    ???+ example

        ```console title="/etc/hosts"
        127.0.0.1 whoami.localhost.com access-guard.localhost.com
        ```

3. Start the services: `docker-compose up -d`

4. Open [http://whoami.localhost.com](http://whoami.localhost.com) in your browser

5. Enter an email that'll be accepted by `access-guard` (e.g. `someone@test.com`)

6. Open [http://localhost:8025](http://localhost:8025) in your browser

7. Open the email and click on the link

8. You should now be redirected to the `whoami` service at [http://whoami.localhost.com](http://whoami.localhost.com)

A cookie is kept by your browser, so closing it there's no need to validate via email
again for as long as that cookie is valid (default 24 hours).
