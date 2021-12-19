# syntax=docker/dockerfile:experimental
######################################
# Base step ##########################
######################################
# Declared as a completely separate target so that we can refer to it in `--from=`
ARG BASE_IMAGE
# hadolint ignore=DL3006
FROM $BASE_IMAGE AS base

######################################
# Release step #######################
######################################
FROM base AS release

ARG SOURCE_HASH
ENV ACCESS_GUARD_SOURCE_HASH $SOURCE_HASH
ARG BUILD_VERSION
ENV ACCESS_GUARD_BUILD_VERSION $BUILD_VERSION

######################################
# Dev builder step ###################
######################################
# Build dev specifics as a separate step so that we can utilise cache better
FROM python:3.10.1-buster AS dev-builder

# Extra Python environment variables
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

# Use Python binaries from venv
ENV PATH="/app/venv/bin:$PATH"

WORKDIR /app

COPY reqs/dev-requirements.txt ./reqs/
COPY --from=base /app/venv venv
RUN --mount=type=cache,target=/root/.cache/pip \
    set -x && \
    pip install --require-hashes --pre -r reqs/dev-requirements.txt ; \
    pip check

######################################
# Dev step ###########################
######################################
# hadolint ignore=DL3006
FROM base AS dev

WORKDIR /app
COPY --from=dev-builder /app/venv venv
