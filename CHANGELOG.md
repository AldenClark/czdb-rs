## v0.1.4

- Fix index range calculation in `search` that could access out-of-bounds data.
- Add unit tests covering boundary IP lookups.
- Add Chinese README and documentation updates.

## v0.1.3

- Added multiple database readers: standard `BufReader`, optional `mmap` (feature), and in-memory loading.

## v0.1.2

- Fixed a binary search indexing bug in the `search` method.

## v0.1.1

- Fixed several bugs to improve stability.
- Enhanced documentation with clearer usage examples and feature descriptions.

## v0.1.0 - Initial Release

- First release of czdb-rs.
- Added support for parsing CZDB-format IP databases.
- Supports both IPv4 and IPv6 lookups.
- Optimized memory usage and disk access with memory-mapped files (mmap).
- Requires database file and key from www.cz88.net.
