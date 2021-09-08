fuzzbucket_version := `pipenv run python setup.py --version 2>/dev/null || echo 0.0.0`
fuzzbucket_release_artifact := 'dist/fuzzbucket_client-' + fuzzbucket_version + '-py3-none-any.whl'
fuzzbucket_s3_prefix := 's3://rstudio-connect-downloads/connect/fuzzbucket'

clean:
  rm -r \
    ./.coverage \
    ./.mypy_cache \
    ./.pytest_cache \
    ./__pycache__ \
    ./build \
    ./dist \
    ./fuzzbucket_client.egg-info \
    ./htmlcov

deps:
  #!/usr/bin/env bash
  set -euo pipefail
  pipenv install --dev
  yarn install

lint:
  #!/usr/bin/env bash
  set -euo pipefail
  pipenv run black --check --diff .
  pipenv run flake8 .
  pipenv run pytest -m mypy --no-cov

fmt:
  pipenv run black .

test coverage_threshold='94':
  pipenv run pytest --cov-fail-under {{ coverage_threshold }}

deploy stage='dev' region='us-east-1':
  npx sls deploy --stage {{ stage }} --region {{ region }} --verbose

logs function='api' stage='dev' region='us-east-1':
  npx sls logs --function {{ function }} --region {{ region }} --stage {{ stage }} --tail

serve-htmlcov:
  pushd ./htmlcov && python -m http.server

release-artifact:
  #!/usr/bin/env bash
  set -euo pipefail
  pipenv run python setup.py bdist_wheel
  echo "::set-output name=tarball::{{ fuzzbucket_release_artifact }}"
  echo "::set-output name=tarball_basename::$(basename '{{ fuzzbucket_release_artifact }}')"

is-releasable:
  pipenv run python setup.py is_releasable

sync-to-s3:
  aws s3 cp --acl bucket-owner-full-control \
    '{{ fuzzbucket_release_artifact }}' \
    "{{ fuzzbucket_s3_prefix }}/{{ fuzzbucket_version }}/$(basename '{{ fuzzbucket_release_artifact }}')"
