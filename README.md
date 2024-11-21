# czdb-rs

[![Crates.io](https://img.shields.io/crates/v/czdb)](https://crates.io/crates/czdb)
[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg)](https://docs.rs/czdb)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/AldenClark/czdb-rs/blob/main/LICENSE-MIT)

czdb-rs is a simple and fast Rust library for parsing CZDB-format IP databases. It supports both IPv4 and IPv6 lookups and uses memory-mapped files (mmap) to keep memory usage low and speed up disk access. Perfect for quick IP geolocation queries with minimal overhead.

Note: The database file and key must be obtained from [www.cz88.net](https://cz88.net/geo-public).

## Usage

```bash
cargo add czdb
```

```rust
let czdb = Czdb::new("Your database file path","Your Key").unwrap();
let ip = IpAddr::from_str("1.0.0.1").unwrap();
let region = czdb.search(ip);
println!("{:?}", region);
```
