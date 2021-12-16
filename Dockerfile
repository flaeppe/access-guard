# syntax=docker/dockerfile:experimental
######################################
# Release step #######################
######################################
ARG BASE_IMAGE
# hadolint ignore=DL3006
FROM $BASE_IMAGE AS release

ARG SOURCE_HASH
ENV ACCESS_GUARD_SOURCE_HASH $SOURCE_HASH
ARG BUILD_VERSION
ENV ACCESS_GUARD_BUILD_VERSION $BUILD_VERSION

######################################
# Dev step ###########################
######################################
# hadolint ignore=DL3006
FROM $BASE_IMAGE as dev

USER root
WORKDIR /app
COPY reqs/dev-requirements.txt ./reqs/
RUN --mount=type=cache,target=/root/.cache/pip \
    set -x && \
    pip install --require-hashes --pre -r reqs/dev-requirements.txt ; \
    pip check
USER app
