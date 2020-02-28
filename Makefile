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
	pip install -r dev-requirements.txt
	pip install -r requirements.txt
	npm install

.PHONY: lint
lint:
	black --check --diff .
	flake8 .

.PHONY: test
test:
	pytest --cov=boxbot --cov=boxbot_client --cov-fail-under=$(COVERAGE_THRESHOLD) -v --disable-warnings

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
	python ./generate_image_aliases.py $@
	black $@

custom.yml: generate_api_key_names.py
	python ./generate_api_key_names.py $(GITHUB_ORG) $(GITHUB_TEAM) $@

.PHONY: install-client
install-client:
	python setup.py install
