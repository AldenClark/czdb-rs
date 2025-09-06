//! # CZDB Database Library
//!
//! A Rust library for parsing and querying CZ-format IP geolocation databases.
//!
//! ## Features
//! - Supports both IPv4 and IPv6 address queries.
//! - Implements efficient binary search for IP data lookup.
//! - Optional memory-mapped file support (`mmap` feature) for optimized memory usage and query performance.
//!
//! ## Usage
//!
//! 1. Create a `Czdb` instance by loading the database file and providing a decryption key:
//! ```rust,ignore
//! use czdb::Czdb;
//!
//! let db_path = "path/to/your/czdb_file";
//! let key = "your_base64_key";
//! let czdb = Czdb::new(db_path, key).expect("Failed to load database");
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
//! ## Error Handling
//! The following errors might occur when loading the database:
//! - `DatabaseFileReadError`: Failed to read the database file.
//! - `KeyDecodingError`: Invalid base64 format for the decryption key.
//! - `DecryptionError`: Decryption failed.
//! - `InvalidClientId`: The client ID in the database file is invalid.
//! - `DatabaseExpired`: The database file has expired.
//! - `DatabaseFileCorrupted`: The database file is corrupted or contains invalid data.
//!
//! ## Notes
//! - The database file must be in a supported CZDB format, and the decryption key must be in valid Base64 format.
//! - The type of IP address queried must match the database type (IPv4 or IPv6).
//! - The database file and key must be obtained from [www.cz88.net](https://cz88.net/geo-public).
//!
//! # 纯真CZDB解析库
//!
//! 这是一个用于解析和查询 CZDB 格式 IP 地理位置数据库的 Rust 库。
//!
//! ## 功能
//! - 支持 IPv4 和 IPv6 地址查询。
//! - 提供高效的二分查找算法定位 IP 数据。
//! - 可选的 mmap 支持（`mmap` feature）以优化内存占用和查询性能
//!
//! ## 使用方法
//!
//! 1. 创建 `Czdb` 实例，加载数据库文件并提供解密密钥：
//! ```rust,ignore
//! use czdb::Czdb;
//!
//! let db_path = "path/to/your/czdb_file";
//! let key = "your_base64_key";
//! let czdb = Czdb::new(db_path, key).expect("Failed to load database");
//! ```
//!
//! 2. 查询 IP 地址对应的地理位置数据：
//! ```rust,ignore
//! use std::net::IpAddr;
//! let ip: IpAddr = "8.8.8.8".parse().unwrap();
//! if let Some(location) = czdb.search(ip) {
//!     println!("Location for IP {}: {}", ip, location);
//! } else {
//!     println!("No location data found for IP {}", ip);
//! }
//! ```
//!
//! ## 错误处理
//! 加载数据库时可能会遇到以下错误：
//! - `DatabaseFileReadError`: 数据库文件读取失败。
//! - `KeyDecodingError`: 解密密钥格式无效。
//! - `DecryptionError`: 解密失败。
//! - `InvalidClientId`: 数据库文件的客户端 ID 无效。
//! - `DatabaseExpired`: 数据库文件已过期。
//! - `DatabaseFileCorrupted`: 数据库文件损坏或数据无效。
//!
//! ## 注意事项
//! - 数据库文件需要是支持的 CZDB 格式，且加密密钥需为有效的 Base64 格式。
//! - 查询的 IP 地址类型必须与数据库类型 (IPv4 或 IPv6) 匹配。
//! - 具体的数据库文件和密钥，请从 [www.cz88.net](https://cz88.net/geo-public) 获取。

use aes::{
    Aes128,
    cipher::{Key, KeyInit},
};
use base64::{Engine, engine::general_purpose};
use byteorder::{LittleEndian, ReadBytesExt};
use cipher::{BlockDecryptMut, block_padding::NoPadding};
#[cfg(feature = "mmap")]
use memmap2::{Mmap, MmapOptions};
use rmpv::{Value, decode::read_value};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Cursor, Read, Seek, SeekFrom},
    net::IpAddr,
    ops::Deref,
    vec,
};

/// Container for database binary data, which can be backed by a `Vec<u8>`
/// or a memory-mapped file when the `mmap` feature is enabled.
#[derive(Debug)]
enum DbBytes {
    Vec(Vec<u8>),
    #[cfg(feature = "mmap")]
    Mmap(Mmap),
}

impl Deref for DbBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            DbBytes::Vec(v) => v.as_slice(),
            #[cfg(feature = "mmap")]
            DbBytes::Mmap(m) => m,
        }
    }
}

/// Represents the type of database (IPv4 or IPv6).
/// Provides utility methods for operations related to IP types.
#[derive(Debug)]
enum DbType {
    Ipv4,
    Ipv6,
}
impl DbType {
    /// Checks whether the given `IpAddr` matches the database type.
    pub fn compare(&self, ip: &IpAddr) -> bool {
        match self {
            DbType::Ipv4 => ip.is_ipv4(),
            DbType::Ipv6 => ip.is_ipv6(),
        }
    }
    /// Returns the length of an index block for the database type.
    pub fn index_block_len(&self) -> usize {
        match self {
            DbType::Ipv4 => 13,
            DbType::Ipv6 => 37,
        }
    }
    /// Returns the length of the bytes for the database type (IPv4: 4 bytes, IPv6: 16 bytes).
    pub fn bytes_len(&self) -> usize {
        match self {
            DbType::Ipv4 => 4,
            DbType::Ipv6 => 16,
        }
    }
}

/// Provides decryption functionality for geo data using a key.
#[derive(Debug)]
struct GeoDataDecryptor {
    key_bytes: Vec<u8>,
}

impl GeoDataDecryptor {
    /// Creates a new decryptor using a base64-encoded key.
    fn new(base64_key: &str) -> Result<Self, base64::DecodeError> {
        let key_bytes = general_purpose::STANDARD.decode(base64_key)?;
        Ok(Self { key_bytes })
    }
    /// Decrypts the input data using XOR with the stored key.
    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let key_length = self.key_bytes.len();
        data.iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ self.key_bytes[i % key_length])
            .collect()
    }
}

/// Enum representing possible errors in the CZ database operations.
#[derive(Debug, thiserror::Error)]
pub enum CzError {
    #[error("Failed to read the database file: {0}")]
    DatabaseFileReadError(#[from] std::io::Error),
    #[error("Failed to decode the key from base64: {0}")]
    KeyDecodingError(#[from] base64::DecodeError),
    #[error("Decryption operation failed")]
    DecryptionError,
    #[error("Invalid client ID")]
    InvalidClientId,
    #[error("The database file has expired")]
    DatabaseExpired,
    #[error("The database file is corrupted or contains invalid data")]
    DatabaseFileCorrupted,
}

/// Represents a CZDB database, providing methods to load and search the database for IP geolocation data.
#[derive(Debug)]
pub struct Czdb {
    bindata: DbBytes,
    index_blocks: BTreeMap<Vec<u8>, u32>,
    db_type: DbType,
    column_selection: u32,
    geo_map_data: Option<Vec<u8>>,
}

impl Czdb {
    /// Creates a new `Czdb` instance using a standard `BufReader`.
    ///
    /// # Arguments
    /// - `db_path`: The path to the database file.
    /// - `key`: The base64-encoded decryption key.
    pub fn new(db_path: &str, key: &str) -> Result<Self, CzError> {
        let key_bytes = general_purpose::STANDARD.decode(&key)?;
        let mut file = File::open(db_path)?;
        let mut reader = BufReader::new(&mut file);

        let _version = reader.read_u32::<LittleEndian>()?;
        let client_id = reader.read_u32::<LittleEndian>()?;
        let encrypted_block_size = reader.read_u32::<LittleEndian>()?;

        let mut encrypted_bytes = vec![0; encrypted_block_size as usize];
        reader.read_exact(&mut encrypted_bytes)?;
        let cipher = Aes128::new(Key::<Aes128>::from_slice(&key_bytes));
        let mut decrypted_bytes = cipher
            .decrypt_padded_mut::<NoPadding>(&mut encrypted_bytes)
            .map_err(|_| CzError::DecryptionError)?;

        let first_u32 = decrypted_bytes.read_u32::<LittleEndian>()?;
        if first_u32 >> 20 != client_id {
            return Err(CzError::InvalidClientId);
        }
        let now: u32 = chrono::Local::now()
            .format("%y%m%d")
            .to_string()
            .parse()
            .map_err(|_| CzError::DatabaseFileCorrupted)?;
        if now > first_u32 & 0xFFFFF {
            return Err(CzError::DatabaseExpired);
        };

        let padding_size = decrypted_bytes.read_u32::<LittleEndian>()?;
        let offset = 12 + padding_size + encrypted_block_size;
        reader.seek(SeekFrom::Start(offset as u64))?;
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        let file_size_total = file.metadata()?.len();

        Self::parse(
            DbBytes::Vec(data),
            padding_size,
            encrypted_block_size,
            file_size_total,
            key,
        )
    }

    /// Creates a new `Czdb` instance by memory-mapping the database file.
    #[cfg(feature = "mmap")]
    pub fn new_mmap(db_path: &str, key: &str) -> Result<Self, CzError> {
        let key_bytes = general_purpose::STANDARD.decode(&key)?;
        let mut file = File::open(db_path)?;

        let _version = file.read_u32::<LittleEndian>()?;
        let client_id = file.read_u32::<LittleEndian>()?;
        let encrypted_block_size = file.read_u32::<LittleEndian>()?;

        let mut encrypted_bytes = vec![0; encrypted_block_size as usize];
        file.read_exact(&mut encrypted_bytes)?;
        let cipher = Aes128::new(Key::<Aes128>::from_slice(&key_bytes));
        let mut decrypted_bytes = cipher
            .decrypt_padded_mut::<NoPadding>(&mut encrypted_bytes)
            .map_err(|_| CzError::DecryptionError)?;

        let first_u32 = decrypted_bytes.read_u32::<LittleEndian>()?;
        if first_u32 >> 20 != client_id {
            return Err(CzError::InvalidClientId);
        }
        let now: u32 = chrono::Local::now()
            .format("%y%m%d")
            .to_string()
            .parse()
            .map_err(|_| CzError::DatabaseFileCorrupted)?;
        if now > first_u32 & 0xFFFFF {
            return Err(CzError::DatabaseExpired);
        };

        let padding_size = decrypted_bytes.read_u32::<LittleEndian>()?;
        let mmap = unsafe {
            MmapOptions::new()
                .offset((12 + padding_size + encrypted_block_size) as u64)
                .map(&file)?
        };
        let file_size_total = file.metadata()?.len();

        Self::parse(
            DbBytes::Mmap(mmap),
            padding_size,
            encrypted_block_size,
            file_size_total,
            key,
        )
    }

    /// Creates a new `Czdb` instance from in-memory bytes of the database file.
    pub fn new_from_bytes(mut data: Vec<u8>, key: &str) -> Result<Self, CzError> {
        let key_bytes = general_purpose::STANDARD.decode(&key)?;
        let total_size = data.len() as u64;
        let mut cursor = Cursor::new(&data);

        let _version = cursor.read_u32::<LittleEndian>()?;
        let client_id = cursor.read_u32::<LittleEndian>()?;
        let encrypted_block_size = cursor.read_u32::<LittleEndian>()?;

        let mut encrypted_bytes = vec![0; encrypted_block_size as usize];
        cursor.read_exact(&mut encrypted_bytes)?;
        let cipher = Aes128::new(Key::<Aes128>::from_slice(&key_bytes));
        let mut decrypted_bytes = cipher
            .decrypt_padded_mut::<NoPadding>(&mut encrypted_bytes)
            .map_err(|_| CzError::DecryptionError)?;

        let first_u32 = decrypted_bytes.read_u32::<LittleEndian>()?;
        if first_u32 >> 20 != client_id {
            return Err(CzError::InvalidClientId);
        }
        let now: u32 = chrono::Local::now()
            .format("%y%m%d")
            .to_string()
            .parse()
            .map_err(|_| CzError::DatabaseFileCorrupted)?;
        if now > first_u32 & 0xFFFFF {
            return Err(CzError::DatabaseExpired);
        };

        let padding_size = decrypted_bytes.read_u32::<LittleEndian>()?;
        let offset = 12 + padding_size + encrypted_block_size;
        let bindata_vec = data.split_off(offset as usize);

        Self::parse(
            DbBytes::Vec(bindata_vec),
            padding_size,
            encrypted_block_size,
            total_size,
            key,
        )
    }

    fn parse(
        bindata: DbBytes,
        padding_size: u32,
        encrypted_block_size: u32,
        file_size_total: u64,
        key: &str,
    ) -> Result<Self, CzError> {
        let mut bindata_cursor = Cursor::new(&*bindata);
        let db_type = if bindata_cursor.read_u8()? & 1 == 0 {
            DbType::Ipv4
        } else {
            DbType::Ipv6
        };
        let file_size = bindata_cursor.read_u32::<LittleEndian>()?;
        if file_size_total != (padding_size + encrypted_block_size + 12 + file_size) as u64 {
            return Err(CzError::DatabaseFileCorrupted);
        }
        let _start_index = bindata_cursor.read_u32::<LittleEndian>()?;
        let total_header_block_size = bindata_cursor.read_u32::<LittleEndian>()?;
        let end_index = bindata_cursor.read_u32::<LittleEndian>()?;

        let total_header_block = total_header_block_size / 20;
        let mut buffer = [0; 20];
        let mut index_blocks = BTreeMap::new();
        for _ in 0..total_header_block {
            bindata_cursor.read_exact(&mut buffer)?;
            let ip = buffer[..16].to_vec();
            let data_ptr = u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);
            index_blocks.insert(ip, data_ptr);
        }

        let column_selection_ptr = end_index + db_type.index_block_len() as u32;
        bindata_cursor.seek(SeekFrom::Start(column_selection_ptr as u64))?;
        let column_selection = bindata_cursor.read_u32::<LittleEndian>()?;
        let mut geo_map_data = None;
        if column_selection != 0 {
            let geo_map_size = bindata_cursor.read_u32::<LittleEndian>()?;
            let mut buffer = vec![0; geo_map_size as usize];
            bindata_cursor.read_exact(&mut buffer)?;
            let data = GeoDataDecryptor::new(key)?.decrypt(&buffer);
            geo_map_data = Some(data);
        }

        Ok(Czdb {
            db_type,
            bindata,
            index_blocks,
            column_selection,
            geo_map_data,
        })
    }

    /// Searches the database for the given IP address and returns its geolocation data, if found.
    ///
    /// # Arguments
    /// - `ip`: The IP address to search for.
    ///
    /// # Returns
    /// - `Some(String)` containing the geolocation data if found.
    /// - `None` if the IP address is not in the database or there is an error.
    pub fn search(&self, ip: IpAddr) -> Option<String> {
        if !self.db_type.compare(&ip) {
            return None;
        }
        let ip_bytes = match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let block_len = self.db_type.index_block_len();
        let (_, start_ptr) = self.index_blocks.range(..=ip_bytes.clone()).next_back()?;
        let end_ptr = match self.index_blocks.range(ip_bytes.clone()..).next() {
            Some((_, end_ptr)) => *end_ptr,
            None => *start_ptr + block_len as u32,
        };

        let ip_len = self.db_type.bytes_len();

        let mut l = 0;
        let mut r = (end_ptr as usize - *start_ptr as usize) / block_len - 1;
        while l <= r {
            let m = (l + r) >> 1;
            let p = *start_ptr as usize + m * block_len;
            let start_ip = &self.bindata[p..p + ip_len];
            let end_ip = &self.bindata[p + ip_len..p + ip_len * 2];
            if start_ip <= &ip_bytes && end_ip >= &ip_bytes {
                let data_ptr = u32::from_le_bytes([
                    self.bindata[p + ip_len * 2],
                    self.bindata[p + ip_len * 2 + 1],
                    self.bindata[p + ip_len * 2 + 2],
                    self.bindata[p + ip_len * 2 + 3],
                ]) as usize;
                let data_len = self.bindata[p + ip_len * 2 + 4] as usize;
                let mut region_data = Cursor::new(&self.bindata[data_ptr..data_ptr + data_len]);
                let geo_pos_mix_size = if let Ok(Value::Integer(i)) =
                    read_value(&mut region_data).map_err(|_| CzError::DatabaseFileCorrupted)
                {
                    i.as_u64().unwrap_or(0)
                } else {
                    return None;
                };
                let other_data = if let Ok(Value::String(s)) =
                    read_value(&mut region_data).map_err(|_| CzError::DatabaseFileCorrupted)
                {
                    s.as_str().map_or_else(
                        || String::from("null"),
                        |v| v.trim().split_whitespace().collect::<Vec<_>>().join(" "),
                    )
                } else {
                    return None;
                };
                if geo_pos_mix_size == 0 {
                    return Some(other_data);
                }
                let data_len = ((geo_pos_mix_size >> 24) & 0xff) as usize;
                let data_ptr = (geo_pos_mix_size & 0x00ffffff) as usize;
                if let Some(geo_map_data) = &self.geo_map_data {
                    if geo_map_data.len() >= data_ptr + data_len {
                        let mut region_data =
                            Cursor::new(&geo_map_data[data_ptr..data_ptr + data_len]);
                        if let Ok(value) = read_value(&mut region_data) {
                            if let Value::Array(values) = value {
                                let region = values
                                    .into_iter()
                                    .enumerate()
                                    .filter_map(|(index, v)| {
                                        let column_selected =
                                            ((self.column_selection >> (index + 1)) & 1) == 1;
                                        if column_selected {
                                            let value = v.as_str().map_or("null", |v| v.trim());
                                            Some(format!("{}\t", value))
                                        } else {
                                            None
                                        }
                                    })
                                    .collect::<Vec<String>>()
                                    .join("-");
                                return Some(format!("{} {}", region, other_data));
                            }
                        }
                    }
                };
                return None;
            } else if start_ip > &ip_bytes && r != 0 {
                r = m - 1;
            } else if end_ip < &ip_bytes && l != m {
                l = m + 1;
            } else {
                return None;
            }
        }

        None
    }
}
