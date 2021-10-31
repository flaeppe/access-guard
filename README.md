# Access Guard [![CI](https://github.com/flaeppe/access-guard/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/flaeppe/access-guard/actions/workflows/ci.yml)

A forward authentication service that provides email verification.

## Documentation

You can find the complete documentation of access-guard at
[flaeppe.github.io/access-guard](https://flaeppe.github.io/access-guard).

## Quickstart

A simple use case with a protected [whoami](https://github.com/traefik/whoami) service

```yaml
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

A more in depth description of this example can be found in
[the documentation](https://flaeppe.github.io/access-guard/traefik/).

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

### Docs

The documentation can be built locally and served on `localhost:8000` with the
following command

```sh
make serve-docs
```

If `make sync-local-requirements` is run before this command, all necessary
requirements have been installed

### Install

Install requirements locally (tip: prepare and activate a virtualenv before installing)

```sh
make sync-local-requirements
```
