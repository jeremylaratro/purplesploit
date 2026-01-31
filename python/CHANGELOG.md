# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [6.9.1] - 2026-01-30

### Security
- Replaced xml.etree.ElementTree with defusedxml to prevent XXE attacks in nmap.py, nmap_parser.py, and server.py
- Added path traversal validation before tarfile extraction in plugins/manager.py
- Hardened CORS configuration in API server - defaults to localhost only, configurable via PURPLESPLOIT_CORS_ORIGINS env var
- Implemented rate limiting with slowapi for sensitive API endpoints (/sessions, /credentials, /targets)
- Added error sanitization with debug mode toggle (PURPLESPLOIT_DEBUG env var) to prevent information leakage

### Changed
- Updated dependencies: added defusedxml>=0.7.1 and slowapi>=0.1.9 to requirements.txt and setup.py

## [6.9.0] - 2026-01-30

### Added
- Initial version with comprehensive business logic test suite (155 tests)
- Phase 2 test fixes resolving 107 failing tests in UI commands suite
- Sprint 5 completion with test expansion, documentation, and performance optimizations
