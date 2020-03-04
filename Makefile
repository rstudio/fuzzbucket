COVERAGE_THRESHOLD ?= 75
FUNCTION ?= api
REGION ?= us-east-1
STAGE ?= dev

.PHONY: help
help:
	@echo "Choose your own adventure:"
	@echo "- deploy (STAGE=$(STAGE), REGION=$(REGION))"
	@echo "- deps"
	@echo "- help"
	@echo "- install-client"
	@echo "- lint"
	@echo "- logs (STAGE=$(STAGE), REGION=$(REGION), FUNCTION=$(FUNCTION))"
	@echo "- test (COVERAGE_THRESHOLD=$(COVERAGE_THRESHOLD))"

.PHONY: deps
deps:
	pipenv install --dev
	npm install

.PHONY: lint
lint:
	pipenv run black --check --diff .
	pipenv run flake8 .

.PHONY: test
test:
	pipenv run pytest --cov-fail-under=$(COVERAGE_THRESHOLD)

.PHONY: deploy
deploy:
	npx sls deploy --stage $(STAGE) --region $(REGION) --verbose

.PHONY: logs
logs:
	npx sls logs --function $(FUNCTION) --region $(REGION) --stage $(STAGE) --tail

.PHONY: install-client
install-client:
	python setup.py install
