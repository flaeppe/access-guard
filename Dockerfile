# syntax=docker/dockerfile:experimental
######################################
# Builder step #######################
######################################
ARG BUILD_TARGET=release
FROM python:3.9.7-buster AS builder

# Extra Python environment variables
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

# Use Python binaries from venv
ENV PATH="/app/venv/bin:$PATH"

# Pinned versions
ENV PIP_PIP_VERSION 21.2.4
ENV PIP_PIP_TOOLS_VERSION 6.2.0

# Setup virtualenv
RUN python -m venv /app/venv
WORKDIR /app

# Install Python dependencies
COPY reqs reqs
ARG BUILD_TARGET
RUN --mount=type=cache,target=/root/.cache/pip \
    set -x && \
    pip install pip==$PIP_PIP_VERSION pip-tools==$PIP_PIP_TOOLS_VERSION && \
    pip install --require-hashes --pre -r reqs/requirements.txt && \
    if [ "${BUILD_TARGET}" = "dev" ] ; then \
        pip install --require-hashes --pre -r reqs/dev-requirements.txt ; \
    fi && \
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
COPY --chown=app setup.cfg ./
COPY --from=builder /app/venv venv
COPY --chown=app access_guard access_guard

# TODO: Setup healthcheck

ARG BUILD_TARGET
ENV ACCESS_GUARD_BUILD_TARGET ${BUILD_TARGET}
ENV PYTHONPATH="/app/access_guard:${PYTHONPATH}"

# Source sha
ARG SOURCE_COMMIT
ENV SOURCE_COMMIT $SOURCE_COMMIT

# Set port
EXPOSE 8585

ENTRYPOINT ["python", "-m", "access_guard"]
