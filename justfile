set shell := ["bash", "-c"]

default:
  hatch run lint
  FUZZBUCKET_AUTH_PROVIDER=github-oauth hatch run test
  FUZZBUCKET_AUTH_PROVIDER=oauth hatch run test --cov-append

deps:
  hatch run yarn install

deps-up:
  hatch run yarn upgrade

deploy stage='dev' region='us-east-1':
  npx sls deploy --stage {{ stage }} --region {{ region }} --verbose

logs function='api' stage='dev' region='us-east-1':
  npx sls logs --function {{ function }} --region {{ region }} --stage {{ stage }} --tail
