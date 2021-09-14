MAKEFILE := $(abspath $(lastword $(MAKEFILE_LIST)))

ROOT_DIR ?= $(patsubst %/,%,$(dir $(MAKEFILE)))

DOCKER_DEV_IMAGE := access-guard
DOCKER_RUN := docker-compose run --rm --user="root" --workdir="/app" --entrypoint= $(DOCKER_DEV_IMAGE)


.PHONY: requirements
requirements:
	python3 -m pip install --upgrade wheel
	pip-compile \
		--upgrade --generate-hashes \
		--output-file reqs/requirements.txt \
		reqs/requirements.in
	pip-compile \
		--upgrade --generate-hashes \
		--output-file reqs/dev-requirements.txt \
		reqs/dev-requirements.in


.PHONY: build
build: export DOCKER_SCAN_SUGGEST=false
build: export DOCKER_BUILDKIT=1
build: export COMPOSE_DOCKER_CLI_BUILD=1
build:
	docker-compose build $(DOCKER_DEV_IMAGE)


.PHONY: test
test: test := -vv $(test)
test:
	$(DOCKER_RUN) pytest $(test) access_guard/


.PHONY: mypy
mypy:
	@$(DOCKER_RUN) mypy --config-file setup.cfg $(mypy)
