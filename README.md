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
of managing instances launched from arbitrary AMIs with anything remotely
resembling complex networking needs, then `fuzzbucket` is probably not a good
fit.

If you need your EC2 instances to be running for more than a few hours/days by
default, then `fuzzbucket` is probably not what you need.


## usage

When working with a deployed `fuzzbucket` API, the `fuzzbucket-client` may be
used to do all the things:

```bash
# install fuzzbucket-client via setup.py with python3.6+
python setup.py install
```

```bash
# get some help
fuzzbucket-client --help
```

As described in this help text, the client tool requires configuration of the
API URL via the following environment variable:

```bash
export FUZZBUCKET_URL='https://fuzzbucket.example.com/prod'
```

> If you have access to the API provisioning tooling and resources, this value
> is printed at the end of deployment and also available via the
> `serverless`/`sls` tool with `npx sls info --stage prod`.
>
> :warning: Without having the `serverless`/`sls` tooling and necessary AWS
> access, you must get this value from someone who does.

Exactly how you choose to manage this environment variable is up to you, such
as by including it in your shell configuration (`~/.bashrc`, `~/.zshrc`) or
by using a tool like [autoenv](https://github.com/inishchith/autoenv).

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

### prerequisites

Defining a custom YAML file for use by `serverless.yml`, e.g.:

```yaml
# custom-path.yml
allowedGithubOrgs: VerySeriousOrg
branding: Very Serious Fuzzbucket
flaskSecretKey: zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
dynamodb:
  start:
    migrate: true
  stages:
  - prod
oauth:
  clientID: yyyyyyyyyyyyyyyyyyyy
  clientSecret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
wsgi:
  app: fuzzbucket.deferred_app
  packRequirements: false
```

* `allowedGithubOrgs` is a space-delimited string of GitHub organizations, to
  at least one of which any authenticating user *must* belong.
* `branding` is an arbitrary string which is used in the OAuth2 flow to provide
  a hint of customization, reduce confusion, nice human things.
* `flaskSecretKey` is set as the Flask app's `secret_key` attribute for session
  security.
* `oauth` section contains `clientID` and `clientSecret` values which must be
  set to the values provided upon [registering your GitHub OAuth2
  app](https://developer.github.com/v3/guides/basics-of-authentication/#registering-your-app)
  specific to your deployment of Fuzzbucket.

:warning: Notably, the custom sections `dynamodb` and `wsgi` _must_ be defined
when providing a custom YAML file, as the `serverless` framework does not
provide a way to merge sections by default (although plugins exist). The values
in the above example are suitable and should work.

```bash
export FUZZBUCKET_CUSTOM_prod='custom-path.yml'
```

### cycle

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

These commands are expected to be re-run as needed, such as after modifying the
custom YAML described in the prerequisites section above.


## changelog

Please see the [CHANGELOG](./CHANGELOG.md).

## license

Please see the [LICENSE](./LICENSE.md).
