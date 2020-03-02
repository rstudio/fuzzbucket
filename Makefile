COVERAGE_THRESHOLD ?= 75
FUNCTION ?= list
GITHUB_ORG ?= rstudio
GITHUB_TEAM ?= connect
REGION ?= us-east-1
STAGE ?= dev

.PHONY: help
help:
	@echo "Choose your own adventure:"
	@echo "- clean"
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
	pipenv run pytest --cov=fuzzbucket --cov=fuzzbucket_client --cov-fail-under=$(COVERAGE_THRESHOLD) -v --disable-warnings

.PHONY: deploy
deploy:
	npx sls deploy --stage $(STAGE) --region $(REGION) --verbose

.PHONY: logs
logs:
	npx sls logs --function $(FUNCTION) --region $(REGION) --stage $(STAGE) --tail

.PHONY: clean
clean:
	$(RM) image_aliases.py custom.yml

image_aliases.py: generate_image_aliases.py
	pipenv run python ./generate_image_aliases.py $@
	pipenv run black $@

custom.yml: generate_api_key_names.py
	pipenv run python ./generate_api_key_names.py $(GITHUB_ORG) $(GITHUB_TEAM) $@

.PHONY: install-client
install-client:
	python setup.py install
