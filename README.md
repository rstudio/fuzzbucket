# fuzzbucket

The `fuzzbucket` API and `fuzzbucket-client` command line tool are intended to
work together to provide humans with a simplified means to perform
["CRUD"](https://en.wikipedia.org/wiki/Create,_read,_update_and_delete)-like
operations on ephemeral EC2 instances ("boxes") in a managed VPC.

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
# install fuzzbucket-client via pip with python3.9+
pip install fuzzbucket-client
```

```bash
# get some help
fuzzbucket-client --help
```

As described in this help text, the client tool requires configuration of the
API URL via the following environment variable:

```bash
# e.g.:
export FUZZBUCKET_URL='https://fuzzbucket.example.com/prod'
```

> If you have access to the API provisioning tooling and resources, this value
> is printed at the end of deployment and also available via the
> `serverless`/`sls` tool with `npx sls info --stage prod`.
>
> :warning: Without having the `serverless`/`sls` tooling and necessary AWS
> access, you must get this value from someone who does.

Exactly how you choose to manage this environment variable is up to you, such as
by including it in your shell configuration (`~/.bashrc`, `~/.zshrc`) or by
using a tool like [direnv](https://direnv.net/).

## development

Prerequisites for development are:

- `just`
- `yarn`
- `hatch`

The `just` tool may be installed via `brew` on macOS and [other ways,
too](https://github.com/casey/just#installation). Similarly, the `yarn` tool may
be installed via `brew` on macOS and [other ways,
too](https://yarnpkg.com/getting-started/install). The `hatch` tool may be
installed via `pip`.

Once these prerequisites are available, the default workflow is nearly identical
to what is captured in the [github workflow](./.github/workflows/main.yml):

```bash
just deps

# BEGIN editing, linting, testing loop {

# edit edit edit
just lint
just test

# } END editing, linting, testing loop
```

## deployment

Deploying the `fuzzbucket` API requires AWS credentials with rights to
create all of the resources managed by the `serverless` framework and
additional resources defined in the [serverless config](./serverless.yml).

### prerequisites

Define a YAML config file and environment variable to use it via
`serverless.yml`, e.g.:

```bash
cp -v ./default-config.yml ./my-config.yml

# edit ./my-config.yml

export FUZZBUCKET_CONFIG_prod='my-config.yml'
```

The copied content of [`./default-config.yml`](./default-config.yml) contains
comments about the structure and meaning of the file.

> **NOTE**: Existing deployments may be using a config format and environment
> variable of the form that uses the word "custom", e.g.
> `FUZZBUCKET_CUSTOM_prod=custom-mine.yml`. This format is no longer supported and must be
> migrated to the new format via the `lint-config` script:
>
> ```bash
> hatch run lint-config ./custom-mine.yml >my-config.yml
>
> # edit ./my-config.yml
>
> export FUZZBUCKET_CONFIG_prod='my-config.yml'
> ```

#### optional IAM role customization

If the IAM role used by the lambda functions requires customization, this may be
done by defining a YAML file and environment variable, e.g.:

```bash
cp -v ./default-iam-role-statements.yml ./my-iam-role-statements.yml

# edit ./my-iam-role-statements.yml

export FUZZBUCKET_IAM_ROLE_STATEMENTS_prod='my-iam-role-statements.yml'
```

#### optional CloudFormation resource customization

If the CloudFormation resources managed via `serverless.yml` require
customization, this may be done by defining a YAML file and environment
variable, e.g.:

```bash
cp -v ./default-resources.yml ./my-resources.yml

# edit ./my-resources.yml

export FUZZBUCKET_RESOURCES_prod='my-resources.yml'
```

#### combined config and customizations

As each of the config and customization files is merged via a distinct top-level
key, they may all be combined and managed as a single file, e.g.:

```bash
cat \
  ./my-config.yml \
  <(echo) \
  ./my-iam-role-statements.yml \
  <(echo) \
  ./my-resources.yml | tee ./combo-config.yml

# edit ./combo-config.yml

export FUZZBUCKET_CONFIG_prod='combo-config.yml'
export FUZZBUCKET_RESOURCES_prod='combo-config.yml'
export FUZZBUCKET_IAM_ROLE_STATEMENTS_prod='combo-config.yml'
```

### management lifecycle

Prior to deployment, one's config file should be checked via the `lint-config`
script:

```bash
# output a diff, if any:
hatch run lint-config --diff ./path-to-config.yml

# write back the complete config to the same path:
hatch run lint-config --write ./path-to-config.yml
```

The `just deploy` target will run the necessary `serverless` command to create
the whole shebang.

```bash
# deploy to STAGE=dev in REGION=us-east-1
just deploy
```

```bash
# deploy to STAGE=prod in REGION=us-west-2
just deploy prod us-west-2
```

These commands are expected to be re-run as needed, such as after modifying the
YAML config described in the prerequisites section above.

## changelog

Please see the [CHANGELOG](./CHANGELOG.md).

## license

Please see the [LICENSE](./LICENSE.md).
