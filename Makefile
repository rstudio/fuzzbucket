STAGE ?= dev
REGION ?= us-east-1

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
	npm install

.PHONY: lint
lint:
	black --check --diff .
	flake8 .

.PHONY: test
test:
	pytest -v --disable-warnings

.PHONY: deploy
deploy:
	npx sls deploy --stage $(STAGE) --region $(REGION) --verbose

.PHONY: quickdeploy
quickdeploy:
	npx sls deploy function --function hello --stage $(STAGE) --region $(REGION) --verbose
