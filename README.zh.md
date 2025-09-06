# czdb-rs

[![Crates.io](https://img.shields.io/crates/v/czdb)](https://crates.io/crates/czdb)
[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg)](https://docs.rs/czdb)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/AldenClark/czdb-rs/blob/main/LICENSE)

czdb-rs 是一个用于查询 CZDB 格式 IP 地理位置数据库的轻量级 Rust 库，支持 IPv4 与 IPv6。库提供多种数据加载方式以满足不同的性能需求：

- 默认使用缓冲读取以降低内存占用
- 可选 `mmap` 特性支持内存映射文件加载
- 支持将数据库完全载入内存以获得最快访问速度

> 数据库文件和密钥需要从 [www.cz88.net](https://cz88.net/geo-public) 获取。

## 使用示例
```bash
cargo add czdb
```

```rust
use czdb::Czdb;
use std::net::IpAddr;

let db = Czdb::new("path/to/your/czdb_file", "your_base64_key")?;
let ip: IpAddr = "8.8.8.8".parse().unwrap();
if let Some(location) = db.search(ip) {
    println!("{} 的位置: {}", ip, location);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

若需英文版文档，请查看 [README.md](README.md)。
