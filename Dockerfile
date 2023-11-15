FROM python:3.11-slim-bullseye

WORKDIR /src

ENV DEBIAN_FRONTEND=noninteractive PYTHONPATH=/src:$PYTHONPATH

RUN apt-get update -y \
  && apt-get upgrade -y \
  && apt-get install -yq curl \
  && pip install -U pip \
  && pip install -U 'setuptools_scm[toml]>=3.4' wheel 'setuptools>=42' \
  && curl -fsSLo /usr/local/bin/aws-lambda-rie https://github.com/aws/aws-lambda-runtime-interface-emulator/releases/latest/download/aws-lambda-rie \
  && chmod -v +x /usr/local/bin/aws-lambda-rie

COPY . . 

RUN install -v -m 0755 docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["fuzzbucket.deferred_app"]
