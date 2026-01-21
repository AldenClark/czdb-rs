use aes::{
    Aes128,
    cipher::{Key, KeyInit},
};
use base64::{Engine, engine::general_purpose};
use byteorder::{LittleEndian, ReadBytesExt};
use cipher::{BlockDecryptMut, block_padding::Pkcs7};
use rmpv::{Value, decode::read_value};
use std::{
    cmp::Ordering,
    io::{Cursor, Read, Seek, SeekFrom},
    net::IpAddr,
};

use crate::CzError;

const SUPER_PART_LENGTH: usize = 17;
const HEADER_BLOCK_LENGTH: usize = 20;

/// Database IP version type.
///
/// 数据库 IP 版本类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbType {
    Ipv4,
    Ipv6,
}

impl DbType {
    /// Returns true if the IP matches this database type.
    ///
    /// 判断给定 IP 是否与数据库类型一致。
    pub fn compare(&self, ip: &IpAddr) -> bool {
        match self {
            DbType::Ipv4 => ip.is_ipv4(),
            DbType::Ipv6 => ip.is_ipv6(),
        }
    }

    /// Returns the index block length for this database type.
    ///
    /// 返回该数据库类型的索引块长度。
    pub fn index_block_len(&self) -> usize {
        match self {
            DbType::Ipv4 => 13,
            DbType::Ipv6 => 37,
        }
    }

    /// Returns the IP byte length for this database type.
    ///
    /// 返回该数据库类型的 IP 字节长度。
    pub fn bytes_len(&self) -> usize {
        match self {
            DbType::Ipv4 => 4,
            DbType::Ipv6 => 16,
        }
    }
}

#[derive(Debug)]
struct GeoDataDecryptor {
    key_bytes: Vec<u8>,
}

impl GeoDataDecryptor {
    fn new(key_bytes: Vec<u8>) -> Result<Self, CzError> {
        if key_bytes.is_empty() {
            return Err(CzError::InvalidAesKeyLength(0));
        }
        Ok(Self { key_bytes })
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let key_length = self.key_bytes.len();
        data.iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ self.key_bytes[i % key_length])
            .collect()
    }
}

/// Parsed metadata used for searching.
///
/// 查询所需的解析元数据。
#[derive(Debug)]
pub struct DbMeta {
    pub db_type: DbType,
    pub header_sip: Vec<[u8; 16]>,
    pub header_ptr: Vec<u32>,
    pub column_selection: u64,
    pub geo_map_data: Option<Vec<u8>>,
    pub start_index: u32,
    pub end_index: u32,
}

/// Hyper header info parsed from the encrypted header block.
///
/// 从加密头部解析出来的超头信息。
#[derive(Debug)]
pub struct HyperHeaderInfo {
    pub padding_size: u32,
    pub encrypted_block_size: u32,
}

/// Decode the base64 AES key and validate its length.
///
/// 解码 base64 AES 密钥并校验长度。
pub fn decode_aes_key(key: &str) -> Result<Vec<u8>, CzError> {
    let key_bytes = general_purpose::STANDARD.decode(key)?;
    if key_bytes.len() != 16 {
        return Err(CzError::InvalidAesKeyLength(key_bytes.len()));
    }
    Ok(key_bytes)
}

/// Compare two byte slices for the first `length` bytes.
///
/// 比较两个字节切片的前 `length` 字节。
pub fn compare_bytes(a: &[u8], b: &[u8], length: usize) -> Ordering {
    for i in 0..length {
        if a[i] < b[i] {
            return Ordering::Less;
        } else if a[i] > b[i] {
            return Ordering::Greater;
        }
    }
    Ordering::Equal
}

/// Read and validate the encrypted hyper header.
///
/// 读取并校验加密超头信息。
pub fn read_hyper_header<R: Read>(
    reader: &mut R,
    key_bytes: &[u8],
) -> Result<HyperHeaderInfo, CzError> {
    let _version = reader.read_u32::<LittleEndian>()?;
    let client_id = reader.read_u32::<LittleEndian>()?;
    let encrypted_block_size = reader.read_u32::<LittleEndian>()?;

    let mut encrypted_bytes = vec![0; encrypted_block_size as usize];
    reader.read_exact(&mut encrypted_bytes)?;
    let cipher = Aes128::new(Key::<Aes128>::from_slice(key_bytes));
    let mut decrypted_bytes = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut encrypted_bytes)
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
    }

    let padding_size = decrypted_bytes.read_u32::<LittleEndian>()?;
    Ok(HyperHeaderInfo {
        padding_size,
        encrypted_block_size,
    })
}

/// Parse metadata from in-memory database bytes (after hyper header).
///
/// 从内存数据库字节解析元数据（位于超头之后）。
pub fn parse_meta_from_bytes(
    bindata: &[u8],
    file_size_total: u64,
    padding_size: u32,
    encrypted_block_size: u32,
    key_bytes: &[u8],
) -> Result<DbMeta, CzError> {
    let mut bindata_cursor = Cursor::new(bindata);
    let db_type = if bindata_cursor.read_u8()? & 1 == 0 {
        DbType::Ipv4
    } else {
        DbType::Ipv6
    };
    let file_size = bindata_cursor.read_u32::<LittleEndian>()?;
    if file_size_total != (padding_size + encrypted_block_size + 12 + file_size) as u64 {
        return Err(CzError::DatabaseFileCorrupted);
    }
    let start_index = bindata_cursor.read_u32::<LittleEndian>()?;
    let total_header_block_size = bindata_cursor.read_u32::<LittleEndian>()?;
    let end_index = bindata_cursor.read_u32::<LittleEndian>()?;

    if total_header_block_size % HEADER_BLOCK_LENGTH as u32 != 0 {
        return Err(CzError::DatabaseFileCorrupted);
    }
    let total_header_block = total_header_block_size / HEADER_BLOCK_LENGTH as u32;

    let mut buffer = [0u8; HEADER_BLOCK_LENGTH];
    let mut header_sip = Vec::with_capacity(total_header_block as usize);
    let mut header_ptr = Vec::with_capacity(total_header_block as usize);
    for _ in 0..total_header_block {
        bindata_cursor.read_exact(&mut buffer)?;
        let data_ptr = u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);
        if data_ptr == 0 {
            break;
        }
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&buffer[..16]);
        header_sip.push(ip);
        header_ptr.push(data_ptr);
    }
    if header_sip.is_empty() {
        return Err(CzError::DatabaseFileCorrupted);
    }

    let column_selection_ptr = end_index + db_type.index_block_len() as u32;
    bindata_cursor.seek(SeekFrom::Start(column_selection_ptr as u64))?;
    let column_selection = bindata_cursor.read_u32::<LittleEndian>()? as u64;
    let mut geo_map_data = None;
    if column_selection != 0 {
        let geo_map_size = bindata_cursor.read_u32::<LittleEndian>()?;
        let mut buffer = vec![0; geo_map_size as usize];
        bindata_cursor.read_exact(&mut buffer)?;
        let decryptor = GeoDataDecryptor::new(key_bytes.to_vec())?;
        let data = decryptor.decrypt(&buffer);
        geo_map_data = Some(data);
    }

    Ok(DbMeta {
        db_type,
        header_sip,
        header_ptr,
        column_selection,
        geo_map_data,
        start_index,
        end_index,
    })
}

/// Parse metadata from a file using the data offset.
///
/// 从文件中按偏移解析元数据。
pub fn parse_meta_from_file<R: Read + Seek>(
    reader: &mut R,
    data_offset: u64,
    file_size_total: u64,
    padding_size: u32,
    encrypted_block_size: u32,
    key_bytes: &[u8],
) -> Result<DbMeta, CzError> {
    reader.seek(SeekFrom::Start(data_offset))?;
    let mut super_bytes = [0u8; SUPER_PART_LENGTH];
    reader.read_exact(&mut super_bytes)?;

    let db_type = if super_bytes[0] & 1 == 0 {
        DbType::Ipv4
    } else {
        DbType::Ipv6
    };
    let file_size = u32::from_le_bytes([
        super_bytes[1],
        super_bytes[2],
        super_bytes[3],
        super_bytes[4],
    ]);
    if file_size_total != (padding_size + encrypted_block_size + 12 + file_size) as u64 {
        return Err(CzError::DatabaseFileCorrupted);
    }
    let start_index = u32::from_le_bytes([
        super_bytes[5],
        super_bytes[6],
        super_bytes[7],
        super_bytes[8],
    ]);
    let total_header_block_size = u32::from_le_bytes([
        super_bytes[9],
        super_bytes[10],
        super_bytes[11],
        super_bytes[12],
    ]);
    let end_index = u32::from_le_bytes([
        super_bytes[13],
        super_bytes[14],
        super_bytes[15],
        super_bytes[16],
    ]);

    if total_header_block_size % HEADER_BLOCK_LENGTH as u32 != 0 {
        return Err(CzError::DatabaseFileCorrupted);
    }
    let total_header_block = total_header_block_size / HEADER_BLOCK_LENGTH as u32;

    reader.seek(SeekFrom::Start(data_offset + SUPER_PART_LENGTH as u64))?;
    let mut header_bytes = vec![0u8; total_header_block_size as usize];
    reader.read_exact(&mut header_bytes)?;

    let mut header_sip = Vec::with_capacity(total_header_block as usize);
    let mut header_ptr = Vec::with_capacity(total_header_block as usize);
    for i in (0..header_bytes.len()).step_by(HEADER_BLOCK_LENGTH) {
        let data_ptr =
            u32::from_le_bytes([header_bytes[i + 16], header_bytes[i + 17], header_bytes[i + 18],
                header_bytes[i + 19]]);
        if data_ptr == 0 {
            break;
        }
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&header_bytes[i..i + 16]);
        header_sip.push(ip);
        header_ptr.push(data_ptr);
    }
    if header_sip.is_empty() {
        return Err(CzError::DatabaseFileCorrupted);
    }

    let column_selection_ptr = end_index + db_type.index_block_len() as u32;
    reader.seek(SeekFrom::Start(
        data_offset + column_selection_ptr as u64,
    ))?;
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    let column_selection = u32::from_le_bytes(buf) as u64;

    let mut geo_map_data = None;
    if column_selection != 0 {
        reader.read_exact(&mut buf)?;
        let geo_map_size = u32::from_le_bytes(buf);
        let mut map = vec![0u8; geo_map_size as usize];
        reader.read_exact(&mut map)?;
        let decryptor = GeoDataDecryptor::new(key_bytes.to_vec())?;
        let data = decryptor.decrypt(&map);
        geo_map_data = Some(data);
    }

    Ok(DbMeta {
        db_type,
        header_sip,
        header_ptr,
        column_selection,
        geo_map_data,
        start_index,
        end_index,
    })
}

/// Decode a region payload into a string, applying geo mapping if needed.
///
/// 解析区域数据为字符串，必要时应用地理映射。
pub fn decode_region_from_bytes(region_bytes: &[u8], meta: &DbMeta) -> Option<String> {
    let mut region_data = Cursor::new(region_bytes);
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
        s.as_str().unwrap_or("null").to_string()
    } else {
        return None;
    };
    if geo_pos_mix_size == 0 {
        return Some(other_data);
    }

    let data_len = ((geo_pos_mix_size >> 24) & 0xff) as usize;
    let data_ptr = (geo_pos_mix_size & 0x00ffffff) as usize;
    let geo_map_data = meta.geo_map_data.as_ref()?;
    if data_ptr + data_len > geo_map_data.len() {
        return None;
    }

    let mut region_data = Cursor::new(&geo_map_data[data_ptr..data_ptr + data_len]);
    if let Ok(value) = read_value(&mut region_data) {
        if let Value::Array(values) = value {
            let mut region = String::new();
            for (index, v) in values.into_iter().enumerate() {
                let column_selected = ((meta.column_selection >> (index + 1)) & 1) == 1;
                if column_selected {
                    let mut value = v.as_str().unwrap_or("null");
                    if value.is_empty() {
                        value = "null";
                    }
                    region.push_str(value);
                    region.push('\t');
                }
            }
            region.push_str(&other_data);
            return Some(region);
        }
    }

    None
}

impl DbMeta {
    /// Locate the index range in the header for the given IP bytes.
    ///
    /// 根据 IP 字节在头部索引中定位范围。
    pub fn search_in_header(&self, ip_bytes: &[u8; 16]) -> Option<(u32, u32)> {
        let header_len = self.header_sip.len();
        if header_len == 0 {
            return None;
        }
        let ip_len = self.db_type.bytes_len();
        let mut l: i32 = 0;
        let mut h: i32 = header_len as i32 - 1;
        let mut sptr: u32 = 0;
        let mut eptr: u32 = 0;

        while l <= h {
            let m = (l + h) >> 1;
            let cmp = compare_bytes(ip_bytes, &self.header_sip[m as usize], ip_len);
            if cmp == Ordering::Less {
                h = m - 1;
            } else if cmp == Ordering::Greater {
                l = m + 1;
            } else {
                let idx = m as usize;
                sptr = self.header_ptr[if idx > 0 { idx - 1 } else { idx }];
                eptr = self.header_ptr[idx];
                break;
            }
        }

        if l > h {
            if l == 0 && h <= 0 {
                return None;
            }

            if l < header_len as i32 {
                let idx = l as usize;
                sptr = self.header_ptr[idx - 1];
                eptr = self.header_ptr[idx];
            } else if h >= 0 && (h as usize + 1) < header_len {
                let idx = h as usize;
                sptr = self.header_ptr[idx];
                eptr = self.header_ptr[idx + 1];
            } else {
                sptr = self.header_ptr[header_len - 1];
                eptr = sptr + self.db_type.index_block_len() as u32;
            }
        }

        if sptr == 0 {
            return None;
        }

        Some((sptr, eptr))
    }
}
