# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- acto-critic audit: psptool-core/entry.rs vs entry.py+file.py (#47)
- Translation unit: psptool-core/entry.rs (#46)
- acto-critic audit: psptool-core/fletcher.rs vs utils.fletcher32 (#44)
- Translation unit: psptool-core/fletcher.rs (#42)

### Fixed

### Changed
- Divergence: psptool_core::fletcher32 silently accepts odd-length input; upstream utils.py:291 raises struct.error (#45)
- integration: differential test vs reference Python PSPTool (#18)
