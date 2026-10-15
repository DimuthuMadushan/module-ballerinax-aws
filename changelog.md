# Change Log
This file contains all the notable changes done to the Ballerina AWS package through the releases.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [1.1.0] - 2026-10-14

### Added
- Add custom STS endpoint support for assume-role and web identity credentials
- Add custom SSO and SSO-OIDC endpoint support for IAM Identity Center credentials

### Changed
- Reject custom endpoints that are not absolute http/https URLs at client initialization instead of failing on the first request

## [1.0.2] - 2026-09-03

### Fixed
- Fix the documented resolution order of the default credential provider chain

## [1.0.1] - 2026-08-04

### Fixed
- Add IAM credential setup steps and fix broken links in the documentation
