# CZDB Database Library

A Rust library for parsing and searching CZDB-format IP geolocation databases.

## Highlights

- Three modes: disk (`CzdbDisk`), mmap (`CzdbMmap`), and in-memory (`CzdbMemory`).
- Disk mode prioritizes low memory, mmap balances memory and speed, memory mode is fastest.
- IPv4/IPv6 supported; aligned with official reference behaviors.
- Batch search APIs for small and large batches.

## Modes

- Disk (`CzdbDisk`): lowest memory, higher latency; good for low QPS or constrained environments.
- Mmap (`CzdbMmap`, feature `mmap`): OS page cache, good throughput with low memory footprint.
- Memory (`CzdbMemory`): prebuilt index + string pool, best latency/QPS; highest memory usage.

## Quick Start

### Disk mode

```rust
use czdb::CzdbDisk;
use std::net::IpAddr;

let mut db = CzdbDisk::open("path/to/your.czdb", "your_base64_key")?;
let ip: IpAddr = "8.8.8.8".parse().unwrap();
let res = db.search(ip);
```

### Mmap mode

```rust
use czdb::CzdbMmap;
use std::net::IpAddr;

let db = CzdbMmap::open("path/to/your.czdb", "your_base64_key")?;
let ip: IpAddr = "8.8.8.8".parse().unwrap();
let res = db.search(ip);
```

### Memory mode

```rust
use czdb::CzdbMemory;
use std::net::IpAddr;

let db = CzdbMemory::open("path/to/your.czdb", "your_base64_key")?;
let ip: IpAddr = "8.8.8.8".parse().unwrap();
let res = db.search(ip);
```

## Batch Searches

### Small batches (binary search)

```rust
use czdb::CzdbMemory;
use std::net::IpAddr;

let db = CzdbMemory::open("path/to/your.czdb", "your_base64_key")?;
let ips: Vec<IpAddr> = vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()];
let res = db.search_many(&ips);
```

### Large batches (sort + scan)

```rust
use czdb::CzdbMemory;
use std::net::IpAddr;

let db = CzdbMemory::open("path/to/your.czdb", "your_base64_key")?;
let ips: Vec<IpAddr> = (0..10000)
    .map(|i| IpAddr::from([1, 1, 1, (i % 255) as u8]))
    .collect();
let res = db.search_many_scan(&ips);
```

## Features

- `mmap`: enable `CzdbMmap`

## Docs

- docs.rs builds with all features enabled by default.
- Local build: `cargo doc --all-features`.

## Notes

- Database files and keys must be obtained from https://cz88.net/geo-public.
- Query IP type must match the database type.

---

# CZDB 数据库解析库

这是一个用于解析与查询 CZDB 格式 IP 地理位置数据库的 Rust 库。

## 核心特性

- 三种模式：磁盘（`CzdbDisk`）、mmap（`CzdbMmap`）、内存（`CzdbMemory`）。
- 磁盘模式最省内存，mmap 兼顾内存与速度，内存模式速度最高。
- 支持 IPv4/IPv6，并对齐官方参考实现行为。
- 提供小批量与大批量查询 API。

## 模式对比

- 磁盘模式（`CzdbDisk`）：内存占用最低，延迟较高；适合低 QPS。
- mmap 模式（`CzdbMmap`，`mmap` feature）：利用系统页缓存，吞吐较好且内存占用低。
- 内存模式（`CzdbMemory`）：预构建索引 + 字符串池，延迟最低；内存占用最高。

## 快速开始

### 磁盘模式

```rust
use czdb::CzdbDisk;
use std::net::IpAddr;

let mut db = CzdbDisk::open("path/to/your.czdb", "your_base64_key")?;
let ip: IpAddr = "8.8.8.8".parse().unwrap();
let res = db.search(ip);
```

### mmap 模式

```rust
use czdb::CzdbMmap;
use std::net::IpAddr;

let db = CzdbMmap::open("path/to/your.czdb", "your_base64_key")?;
let ip: IpAddr = "8.8.8.8".parse().unwrap();
let res = db.search(ip);
```

### 内存模式

```rust
use czdb::CzdbMemory;
use std::net::IpAddr;

let db = CzdbMemory::open("path/to/your.czdb", "your_base64_key")?;
let ip: IpAddr = "8.8.8.8".parse().unwrap();
let res = db.search(ip);
```

## 批量查询

### 小批量（二分）

```rust
use czdb::CzdbMemory;
use std::net::IpAddr;

let db = CzdbMemory::open("path/to/your.czdb", "your_base64_key")?;
let ips: Vec<IpAddr> = vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()];
let res = db.search_many(&ips);
```

### 大批量（排序 + 扫描）

```rust
use czdb::CzdbMemory;
use std::net::IpAddr;

let db = CzdbMemory::open("path/to/your.czdb", "your_base64_key")?;
let ips: Vec<IpAddr> = (0..10000)
    .map(|i| IpAddr::from([1, 1, 1, (i % 255) as u8]))
    .collect();
let res = db.search_many_scan(&ips);
```

## 功能开关

- `mmap`：启用 `CzdbMmap`

## 文档

- docs.rs 默认开启全部 feature。
- 本地构建：`cargo doc --all-features`。

## 注意事项

- 数据库文件与密钥需从 https://cz88.net/geo-public 获取。
- 查询的 IP 类型需与数据库类型一致。
