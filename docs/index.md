# Access guard

A forward authentication service that provides email verification.

[![CI](https://github.com/flaeppe/access-guard/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/flaeppe/access-guard/actions/workflows/ci.yml)

---

## Overview

- Limit visitors to only those who successfully verify via email.
  [Where you define](reference.md#email-patterns) which email addresses are allowed to
  verify.
- Provides a great alternative to protecting services with
  [basic auth](https://datatracker.ietf.org/doc/html/rfc7617). As there's no need for
  either shared or individual login credentials.
- Access guard ships as a [docker image](https://docs.docker.com/get-started/overview/#docker-objects)
  and can be started up as an independent service.
- Have a look at ["How it works"](how_it_works.md) to get a better idea of what Access
  guard will be doing.

!!! note

    You will need an SMTP server that Access guard can configure its SMTP client to
    send verification emails to.

## Use cases

### traefik

Access guard is compatible with [traefik's forward auth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/).
View ["Use with traefik's forward auth"](traefik.md) for a walk-through of a
configuration example.
