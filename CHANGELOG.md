# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security

## [0.12.1] - 2022-04-29

### Fixed
- server: remove session token and user when github token
  expiration is detected

## [0.12.0] - 2022-03-17

### Added
- server: ensure usernames are stored in lowercase
- client: warn when mixed-case GitHub usernames are used
- client: log at warning level about `FUZZBUCKET_CREDENTIALS` when
  tty is detected
- support for ed25519 ssh keys

### Security
- dependency upgrades

## [0.11.0] - 2022-01-06

### Added
- client: additional entries in box aliases to ssh username mapping

## [0.10.1] - 2021-11-24

### Changed
- minor housekeeping cleanups

## [0.10.0] - 2021-11-23

### Added
- box updating capabilities

### Changed
- client: accept multiple formats for `--ttl` options

### Security
- dependency upgrades

## [0.9.0] - 2021-09-09

### Added
- client: allow naming of credentials sections

### Changed
- internal: switch from `make` to `just`

## [0.8.1] - 2021-09-08

### Fixed
- packaging configuration to include serverless-wsgi assets
- url un-quoting server side instance tags set via environment variables

## [0.8.0] - 2021-09-08

### Added
- support for custom instance tagging
    - server-side configuration applied to all instances
    - client-side per-instance tagging support

### Changed
- opened tcp port 5900 in default security group to allow VNC traffic

### Removed
- codecov integration following security incident

### Security
- dependency upgrades

## [0.7.0] - 2021-03-29

### Added
- get, list, add, and delete of public keys
    - allow adding public key material from file with alias
    - allow automatic adding `~/.ssh/id_rsa.pub`
    - caching of preferred key alias

### Security
- bumped all Python and Node dependencies

## [0.6.2] - 2021-03-03

### Fixed
- additional debug logging around auth process

### Security
- Updated dependencies to resolve security alerts for `pyyaml`,
  `jinja2`, and `cryptography`.

## [0.6.1] - 2021-01-13

### Fixed
- pypi artifact ordering problems

## [0.6.0] - 2021-01-13

### Added
- logout command to clear user data on the fuzzbucket server side
- allow specifying root volume size
- client: read credentials from `FUZZBUCKET_CREDENTIALS`
  environment variable when available

### Changed
- client: clarity around GitHub username case sensitivity

### Fixed
- server: root EBS volumes will always be deleted on termination
- client: documented installation method via PyPI

### Security
- dependency updates

## [0.5.1] - 2020-12-18

### Added
- client: released via PyPI

### Fixed
- client: long description content type is markdown

## [0.5.0] - 2020-12-16

### Added
- EC2 key pair management

### Fixed
- server: only attempt to import RSA key material into EC2

### Security
- all dependencies updated

## [0.4.3] - 2020-06-17

### Fixed
- use `setuptools_scm` instead of homegrown version thing

## [0.4.2] - 2020-06-15

### Fixed
- add missing step id for creating release so that release uploads work

## [0.4.1] - 2020-06-15

### Fixed
- server: unset `github.token` with `None` instead of trying to `del`
- server: compare key pair name case-insensitively to avoid collisions
- server: handle 500 errors with appropriate content type

## [0.4.0] - 2020-06-09

### Added
- client: option to output data as json
- server: more debug logging

## [0.3.3] - 2020-03-26

### Fixed
- client: ensuring config directory existence
- client: fail login when `FUZZBUCKET_URL` is not defined

## [0.3.2] - 2020-03-25

### Fixed
- documentation around credentials
- help text consistency

## [0.3.1] - 2020-03-25

### Fixed
- client: really skip client setup on login

## [0.3.0] - 2020-03-25

### Added
- client: authentication via GitHub
- client: print hints when not authenticated

### Changed
- docs to emphasize end user experience

### Removed
- client: authentication via API key

## [0.2.1] - 2020-03-20

### Fixed
- client: clarity of python version requirement
- client: version retrieval & printing

## [0.2.0] - 2020-03-18

### Added
- client: box create, delete, and reboot commands
- client: ssh and scp commands
- client: version flag
- server: scope reboot and delete to user
- server: manage image aliases in dynamodb
- server: reaping via ttl tag
- server: image alias management API
- log level configuration

### Changed
- renamed to fuzzbucket (from boxbot)
- server: configurable reap schedule
- server: do a Flask
- server: un-scope image aliases from user

## [0.1.0] - 2020-02-28

### Added
- initial implementation

[Unreleased]: https://github.com/rstudio/fuzzbucket/compare/0.12.1...HEAD
[0.12.1]: https://github.com/rstudio/fuzzbucket/compare/0.12.0...0.12.1
[0.12.0]: https://github.com/rstudio/fuzzbucket/compare/0.11.0...0.12.0
[0.11.0]: https://github.com/rstudio/fuzzbucket/compare/0.10.1...0.11.0
[0.10.1]: https://github.com/rstudio/fuzzbucket/compare/0.10.0...0.10.1
[0.10.0]: https://github.com/rstudio/fuzzbucket/compare/0.9.0...0.10.0
[0.9.0]: https://github.com/rstudio/fuzzbucket/compare/0.8.1...0.9.0
[0.8.1]: https://github.com/rstudio/fuzzbucket/compare/0.8.0...0.8.1
[0.8.0]: https://github.com/rstudio/fuzzbucket/compare/0.7.0...0.8.0
[0.7.0]: https://github.com/rstudio/fuzzbucket/compare/0.6.2...0.7.0
[0.6.2]: https://github.com/rstudio/fuzzbucket/compare/0.6.1...0.6.2
[0.6.1]: https://github.com/rstudio/fuzzbucket/compare/0.6.0...0.6.1
[0.6.0]: https://github.com/rstudio/fuzzbucket/compare/0.5.1...0.6.0
[0.5.1]: https://github.com/rstudio/fuzzbucket/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/rstudio/fuzzbucket/compare/0.4.3...0.5.0
[0.4.3]: https://github.com/rstudio/fuzzbucket/compare/0.4.2...0.4.3
[0.4.2]: https://github.com/rstudio/fuzzbucket/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/rstudio/fuzzbucket/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/rstudio/fuzzbucket/compare/0.3.3...0.4.0
[0.3.3]: https://github.com/rstudio/fuzzbucket/compare/0.3.2...0.3.3
[0.3.2]: https://github.com/rstudio/fuzzbucket/compare/0.3.1...0.3.2
[0.3.1]: https://github.com/rstudio/fuzzbucket/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/rstudio/fuzzbucket/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/rstudio/fuzzbucket/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/rstudio/fuzzbucket/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/rstudio/fuzzbucket/tree/0.1.0
