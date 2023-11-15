#!/bin/sh
# This docker entrypoint script was lovingly lifted from:
# https://www.keithrpetersen.com/blog/python-311-aws-lambda-custom-runtime/

if [ -z "${AWS_LAMBDA_RUNTIME_API}" ]; then
  exec /usr/local/bin/aws-lambda-rie /usr/local/bin/python -m awslambdaric --log-level "debug" "$@"
else
  exec /usr/local/bin/python -m awslambdaric "$@"
fi
