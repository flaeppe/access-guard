MAKEFILE := $(abspath $(lastword $(MAKEFILE_LIST)))

ROOT_DIR ?= $(patsubst %/,%,$(dir $(MAKEFILE)))

DOCKER_DEV_IMAGE := access-guard
DOCKER_RUN := docker-compose run --rm --user="root" --workdir="/app" --entrypoint= $(DOCKER_DEV_IMAGE)


.PHONY: pre-requirements
pre-requirements:
	python3 -m pip install --upgrade wheel


.PHONY: requirements
requirements: pre-requirements
	pip-compile \
		--upgrade --generate-hashes \
		--output-file reqs/requirements.txt \
		reqs/requirements.in
	pip-compile \
		--upgrade --generate-hashes \
		--output-file reqs/dev-requirements.txt \
		reqs/dev-requirements.in


.PHONY: docs-requirements
docs-requirements: pre-requirements
	pip-compile \
		--upgrade --generate-hashes \
		--output-file docs/reqs/requirements.txt \
		docs/reqs/requirements.in


.PHONY: sync-local-requirements
sync-local-requirements:
	pip install \
		pip==$$(cat Dockerfile-base | grep 'ENV PIP_PIP_VERSION' | cut -f3 -d' ') \
		pip-tools==$$(cat Dockerfile-base | grep 'ENV PIP_PIP_TOOLS_VERSION' | cut -f3 -d' ')
	pip-sync \
		reqs/requirements.txt \
		reqs/dev-requirements.txt \
		docs/reqs/requirements.txt


.PHONY: build
build: export DOCKER_SCAN_SUGGEST=false
build: export DOCKER_BUILDKIT=1
build: export COMPOSE_DOCKER_CLI_BUILD=1
build:
	@docker build -f ./Dockerfile-base -t $(DOCKER_DEV_IMAGE):base .
	@docker-compose build $(DOCKER_DEV_IMAGE)


.PHONY: test
test: test := -vv $(test)
test:
	$(DOCKER_RUN) pytest $(test) access_guard/


.PHONY: mypy
mypy:
	@$(DOCKER_RUN) mypy --config-file pyproject.toml $(mypy)


.PHONY: bash
bash:
	$(DOCKER_RUN) bash


.PHONY: serve-docs
serve-docs:
	mkdocs serve
