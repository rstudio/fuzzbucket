# fuzzbucket

The `fuzzbucket` API and `fuzzbucket-client` command line tool are intended to
work together to provide humans with a simplified means to perform the
following operations on ephemeral EC2 instances ("boxes") in a managed VPC:

-    list
-    create
-    reboot
-    delete

Additionally, there is a periodic function that will terminate stale boxes.

[![asciicast](https://asciinema.org/a/4lO70eoiBq9qBhbem9i5dd768.svg)](https://asciinema.org/a/4lO70eoiBq9qBhbem9i5dd768)

## is this for me?

Maybe.

If you are comfortable with direct access to EC2 via AWS authz for the purpose
of managing instances launched from arbitrary AMIs, then `fuzzbucket` is
probably not what you need.

If you need your EC2 instances to be running for more than a few hours/days by
default, then `fuzzbucket` is probably not what you need.

## development

Prerequisites for development are:

-    `make`
-    `npm`
-    `pipenv`

Hopefully `make` is already available :grimacing:. The `npm` tool should be
present if there is a `node` installation present. The `pipenv` tool may be
installed via `pip`.

Once these prerequisites are available, the default workflow is nearly
identical to what is captured in the [github
workflow](./.github/workflows/main.yml):

```bash
make deps

# BEGIN editing, linting, testing loop {

# edit edit edit
make lint
make test

# } END editing, linting, testing loop
```

## deployment

Deploying the `fuzzbucket` API requires AWS credentials with rights to
create all of the resources managed by the `serverless` framework and
additional resources defined in the [serverless config](./serverless.yml).

The `make deploy` target will run the necessary `serverless` command to create
the whole shebang.

```bash
# deploy to STAGE=dev in REGION=us-east-1
make deploy
```

```bash
# deploy to STAGE=prod in REGION=us-west-2
make deploy STAGE=prod REGION=us-west-2
```

## usage

Once the `fuzzbucket` API is deployed, the `fuzzbucket-client` may be used to
do all the things:

```bash
# install fuzzbucket-client via setup.py
python setup.py install
```

```bash
# get some help
fuzzbucket-client --help
```

As described in this help text, the client tool requires configuration of the
API URL and credentials.


If you have access to the API provisioning tooling and resources, these values
are printed at the end of deployment and also available via the
`serverless`/`sls` tool:

```bash
# show info for STAGE=prod
npx sls info --stage prod
```

For example, if the output of `sls info` were to include values of:

```
...
api keys:
  githubperson01: fafaeaeadadacacababaaaaa
  ...
endpoints:
  GET - https://babacaca9000.execute-api.us-east-1.amazonaws.com/prod
  ...
```

then the necessary environment variable configuration would be:

```bash
FUZZBUCKET_URL=https://babacaca9000.execute-api.us-east-1.amazonaws.com/prod
FUZZBUCKET_CREDENTIALS=githubperson01:fafaeaeadadacacababaaaaa
```

> :warning: Without having the `serverless`/`sls` tooling and necessary AWS
> access, you must get these values from someone who does.

Exactly how you choose to manage these environment variables is up to you, but
the default development workflow which uses `pipenv` will automatically source
variables defined in `./.env`. See [the example env](./.example.env) for an
example... env.
