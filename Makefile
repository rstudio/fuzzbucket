.PHONY: help
help:
	@echo Choose your own adventure:
	@echo - deps
	@echo - lint
	@echo - test

.PHONY: deps
deps:
	pip install -r dev-requirements.txt
	pip install -r requirements.txt

.PHONY: lint
lint:
	black --check --diff .
	flake8 .

.PHONY: test
test:
	pytest -v
