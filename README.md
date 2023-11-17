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

Defining a custom YAML file for use by `serverless.yml`, e.g.:

```bash
cp -v ./default-custom.yml ./custom-path.yml

# edit ./custom-path.yml

export FUZZBUCKET_CUSTOM_prod='custom-path.yml'
```

See [`./default-custom.yml`](./default-custom.yml) for comments about the
structure and meaning of the file.

### cycle

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
custom YAML described in the prerequisites section above.


## changelog

Please see the [CHANGELOG](./CHANGELOG.md).

## license

Please see the [LICENSE](./LICENSE.md).
