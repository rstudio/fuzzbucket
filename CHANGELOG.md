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

[Unreleased]: https://github.com/rstudio/fuzzbucket/compare/0.4.0...HEAD
[0.4.0]: https://github.com/rstudio/fuzzbucket/compare/0.3.3...0.4.0
[0.3.3]: https://github.com/rstudio/fuzzbucket/compare/0.3.2...0.3.3
[0.3.2]: https://github.com/rstudio/fuzzbucket/compare/0.3.1...0.3.2
[0.3.1]: https://github.com/rstudio/fuzzbucket/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/rstudio/fuzzbucket/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/rstudio/fuzzbucket/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/rstudio/fuzzbucket/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/rstudio/fuzzbucket/tree/0.1.0
