# syntax=docker/dockerfile:experimental
######################################
# Builder step #######################
######################################
FROM python:3.9.7-buster AS builder

# Extra Python environment variables
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

# Use Python binaries from venv
ENV PATH="/app/venv/bin:$PATH"

# Pinned versions
ENV PIP_PIP_VERSION 21.3.1
ENV PIP_PIP_TOOLS_VERSION 6.4.0

# Setup virtualenv
RUN python -m venv /app/venv
WORKDIR /app

# Install Python dependencies
COPY reqs/requirements.txt ./reqs/
RUN --mount=type=cache,target=/root/.cache/pip \
    set -x && \
    pip install pip==$PIP_PIP_VERSION pip-tools==$PIP_PIP_TOOLS_VERSION && \
    pip install --require-hashes --pre -r reqs/requirements.txt && \
    pip check

######################################
# Runtime step #######################
######################################
FROM python:3.9.7-slim-buster AS runtime

# Extra Python environment variables
ENV XDG_CACHE_HOME /tmp/pip/.cache
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

# Use Python binaries from venv
ENV PATH="/app/venv/bin:$PATH"

# Setup app user and directory
RUN set -x && groupadd -g 7331 app && useradd -r -u 7331 -g app app && \
    mkdir /app && chown -R app:app /app

# Install source code
WORKDIR /app
USER app
COPY --chown=app setup.cfg pyproject.toml ./
COPY --from=builder /app/venv venv
COPY --chown=app access_guard access_guard

# TODO: Setup healthcheck

ENV PYTHONPATH="/app/access_guard:${PYTHONPATH}"

# Set port
EXPOSE 8585

ENTRYPOINT ["python", "-m", "access_guard"]

######################################
# Release step #######################
######################################
FROM runtime AS release

ARG SOURCE_HASH
ENV ACCESS_GUARD_SOURCE_HASH $SOURCE_HASH
ARG BUILD_VERSION
ENV ACCESS_GUARD_BUILD_VERSION $BUILD_VERSION

######################################
# Dev step ###########################
######################################
FROM runtime as dev

USER root
COPY reqs/dev-requirements.txt ./reqs/
RUN --mount=type=cache,target=/root/.cache/pip \
    set -x && \
    pip install --require-hashes --pre -r reqs/dev-requirements.txt ; \
    pip check
USER app
