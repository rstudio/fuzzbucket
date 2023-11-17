set shell := ["bash", "-c"]

default:
  hatch run lint
  hatch run test

deps:
  hatch run yarn install

deps-up:
  hatch run yarn upgrade

deploy stage='dev' region='us-east-1':
  npx sls deploy --stage {{ stage }} --region {{ region }} --verbose

logs function='api' stage='dev' region='us-east-1':
  npx sls logs --function {{ function }} --region {{ region }} --stage {{ stage }} --tail
