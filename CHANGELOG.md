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


## [0.1.1] - 2021-05-17

### Changed
- Change several allocations to be statically sized instead, improving performance slightly.

### Removed
- Dependency on `num_traits`.

### Fixed
- Error in calculating the S key that resulted in an incorrect proof once every ~250 authentications.
- Bug where client version always used the static version of the large safe prime.

## [0.1.0] - 2021-04-21

### Added
- Initial release

[0.1.1]: https://github.com/gtker/wow_srp/releases/tag/v0.1.1
[0.1.0]: https://github.com/gtker/wow_srp/tree/39f5ef7ce9e17dd85381b2c48c06b174777469c1
