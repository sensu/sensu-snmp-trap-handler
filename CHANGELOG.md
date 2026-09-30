# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic
Versioning](http://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- SNMPv3 support (USM authentication/privacy) via new `--security-level`, `--username`,
  `--auth-protocol`, `--auth-passphrase`, `--priv-protocol`, `--priv-passphrase`,
  `--context-name`, and `--engine-id` flags/annotations/env vars. SNMPv1/v2c behavior is
  unchanged.

### Changed
- Updated SNMP library dependency from the archived `github.com/soniah/gosnmp` to its
  canonical successor `github.com/gosnmp/gosnmp` v1.45.0.
- Bumped minimum Go version to 1.24 (required by the updated gosnmp dependency).

## [0.2.2] - 20201-04-26

### Changed
- Works with proxy entity, no longer requires entity ip address to exist
- Added links to the MIB files in README

## [0.2.1] - 2020-07-24

### Changed
- Clean up following transfer

## [0.2.0] - 2020-07-22

### Changed
- Changed message from static format to template

## [0.1.0] - 2020-04-19

### Added
- Initial release
