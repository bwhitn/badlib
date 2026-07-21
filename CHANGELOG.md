# Changelog

All notable changes to this project will be documented in this file.

## 0.1.0 - Unreleased

- Initial project scaffold.
- Added BADD compressed object reader/writer support from malarchive.
- Added quick file type identification support from malarchive.
- Renamed the distribution and import package to `badlib`.
- Installed and verified the local development test tooling.
- Fixed default compressed reads returning zero-filled middle data when block
  metadata had not already been built by verification.
- Added default and caller-configurable BADD output-size, block-count, and
  compression-ratio limits with layout validation before allocation.
- Bounded RTF marker scanning to the first 256 KiB of input.
