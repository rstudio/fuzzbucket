COVERAGE_THRESHOLD ?= 96
FUNCTION ?= api
REGION ?= us-east-1
STAGE ?= dev

SHELL := /bin/bash

FUZZBUCKET_VERSION := $(shell pipenv run python setup.py --version)
FUZZBUCKET_RELEASE_ARTIFACT := dist/fuzzbucket_client-$(FUZZBUCKET_VERSION)-py3-none-any.whl
FUZZBUCKET_S3_PREFIX := s3://rstudio-connect-downloads/connect/fuzzbucket

.PHONY: help
help:
	@echo "Choose your own adventure:"
	@echo "- clean"
	@echo "- deploy (STAGE=$(STAGE), REGION=$(REGION))"
	@echo "- deps"
	@echo "- help"
	@echo "- lint"
	@echo "- logs (STAGE=$(STAGE), REGION=$(REGION), FUNCTION=$(FUNCTION))"
	@echo "- test (COVERAGE_THRESHOLD=$(COVERAGE_THRESHOLD))"

.PHONY: clean
clean:
	$(RM) -r \
		./.coverage \
		./.mypy_cache \
		./.pytest_cache \
		./__pycache__ \
		./build \
		./dist \
		./fuzzbucket_client.egg-info \
		./htmlcov

.PHONY: deps
deps:
	pipenv install --dev
	npm install

.PHONY: lint
lint:
	pipenv run black --check --diff .
	pipenv run flake8 .
	pipenv run pytest -m mypy --no-cov

.PHONY: test
test:
	pipenv run pytest --cov-fail-under=$(COVERAGE_THRESHOLD)

.PHONY: deploy
deploy:
	npx sls deploy --stage $(STAGE) --region $(REGION) --verbose

.PHONY: logs
logs:
	npx sls logs --function $(FUNCTION) --region $(REGION) --stage $(STAGE) --tail

.PHONY: serve-htmlcov
serve-htmlcov:
	pushd ./htmlcov && python -m http.server

.PHONY: release-artifact
release-artifact: $(FUZZBUCKET_RELEASE_ARTIFACT)
	@echo "::set-output name=tarball::$(FUZZBUCKET_RELEASE_ARTIFACT)"
	@echo "::set-output name=tarball_basename::$(notdir $(FUZZBUCKET_RELEASE_ARTIFACT))"


$(FUZZBUCKET_RELEASE_ARTIFACT): $(wildcard fuzzbucket_client/*.py) setup.py
	pipenv run python setup.py bdist_wheel

.PHONY: is-releasable
is-releasable:
	pipenv run python setup.py is_releasable

.PHONY: sync-to-s3
sync-to-s3:
	aws s3 cp --acl bucket-owner-full-control \
		$(FUZZBUCKET_RELEASE_ARTIFACT) \
		$(FUZZBUCKET_S3_PREFIX)/$(FUZZBUCKET_VERSION)/$(notdir $(FUZZBUCKET_RELEASE_ARTIFACT))
