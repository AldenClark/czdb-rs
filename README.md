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
use czdb::Czdb;

let db_path = "path/to/your/czdb_file";
let key = "your_base64_key";
let czdb = Czdb::new(db_path, key).expect("Failed to load database");
```

```rust
use std::net::IpAddr;
let ip: IpAddr = "8.8.8.8".parse().unwrap();
if let Some(location) = czdb.search(ip) {
    println!("Location for IP {}: {}", ip, location);
} else {
    println!("No location data found for IP {}", ip);
}
```
