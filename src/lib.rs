//! # CZDB Database Library
//!
//! A Rust library for parsing and searching CZ-format IP geolocation databases.
//!
//! ## Features
//! - Supports both IPv4 and IPv6 address searches.
//! - Disk-based search (`CzdbDisk`) for low memory usage.
//! - Optional memory-mapped file support (`mmap` feature) via `CzdbMmap`.
//! - In-memory accelerated search via `CzdbMemory` (available by default).
//!
//! ## Usage
//!
//! 1. Create a database instance by loading the database file and providing a decryption key:
//! ```rust,ignore
//! use czdb::CzdbDisk;
//!
//! let db_path = "path/to/your/czdb_file";
//! let key = "your_base64_key";
//! let mut czdb = CzdbDisk::open(db_path, key).expect("Failed to load database");
//! ```
//!
//! 2. Search for IP address geolocation data:
//! ```rust,ignore
//! use std::net::IpAddr;
//!
//! let ip: IpAddr = "8.8.8.8".parse().unwrap();
//! if let Some(location) = czdb.search(ip) {
//!     println!("Location for IP {}: {}", ip, location);
//! } else {
//!     println!("No location data found for IP {}", ip);
//! }
//! ```
//!
//! # 纯真CZDB解析库
//!
//! 这是一个用于解析和查询 CZDB 格式 IP 地理位置数据库的 Rust 库。
//!
//! ## 功能
//! - 支持 IPv4 和 IPv6 地址查询。
//! - 提供磁盘搜索（`CzdbDisk`）、可选 mmap（`CzdbMmap`）和可选内存加速（`CzdbMemory`）。
//!
//! ## 使用方法
//!
//! 1. 创建实例并加载数据库：
//! ```rust,ignore
//! use czdb::CzdbDisk;
//!
//! let db_path = "path/to/your/czdb_file";
//! let key = "your_base64_key";
//! let mut czdb = CzdbDisk::open(db_path, key).expect("Failed to load database");
//! ```
//!
//! 2. 查询 IP 数据：
//! ```rust,ignore
//! use std::net::IpAddr;
//! let ip: IpAddr = "8.8.8.8".parse().unwrap();
//! if let Some(location) = czdb.search(ip) {
//!     println!("Location for IP {}: {}", ip, location);
//! } else {
//!     println!("No location data found for IP {}", ip);
//! }
//! ```

mod common;
mod disk;
mod memory;
#[cfg(feature = "mmap")]
#[cfg_attr(docsrs, doc(cfg(feature = "macros")))]
mod mmap;

pub use common::DbType;
pub use disk::CzdbDisk;
pub use memory::CzdbMemory;
#[cfg(feature = "mmap")]
#[cfg_attr(docsrs, doc(cfg(feature = "macros")))]
pub use mmap::CzdbMmap;

/// Possible errors returned by CZDB operations.
///
/// CZDB 操作可能返回的错误。
#[derive(Debug, thiserror::Error)]
pub enum CzError {
    #[error("Failed to read the database file: {0}")]
    DatabaseFileReadError(#[from] std::io::Error),
    #[error("Failed to decode the key from base64: {0}")]
    KeyDecodingError(#[from] base64::DecodeError),
    #[error("Invalid AES key length: expected 16, got {0}")]
    InvalidAesKeyLength(usize),
    #[error("Decryption operation failed")]
    DecryptionError,
    #[error("Invalid client ID")]
    InvalidClientId,
    #[error("The database file has expired")]
    DatabaseExpired,
    #[error("The database file is corrupted or contains invalid data")]
    DatabaseFileCorrupted,
}
