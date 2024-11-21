use aes::{
    cipher::{Key, KeyInit},
    Aes128,
};
use base64::{engine::general_purpose, Engine};
use byteorder::{LittleEndian, ReadBytesExt};
use cipher::{block_padding::NoPadding, BlockDecryptMut};
use memmap2::{Mmap, MmapOptions};
use rmpv::{decode::read_value, Value};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Cursor, Read, Seek, SeekFrom},
    net::IpAddr,
    vec,
};

#[derive(Debug)]
enum DbType {
    Ipv4,
    Ipv6,
}
impl DbType {
    pub fn compare(&self, ip: &IpAddr) -> bool {
        match self {
            DbType::Ipv4 => ip.is_ipv4(),
            DbType::Ipv6 => ip.is_ipv6(),
        }
    }
    pub fn index_block_len(&self) -> usize {
        match self {
            DbType::Ipv4 => 13,
            DbType::Ipv6 => 37,
        }
    }
    pub fn bytes_len(&self) -> usize {
        match self {
            DbType::Ipv4 => 4,
            DbType::Ipv6 => 16,
        }
    }
}

struct GeoDataDecryptor {
    key_bytes: Vec<u8>,
}

impl GeoDataDecryptor {
    fn new(base64_key: &str) -> Result<Self, base64::DecodeError> {
        let key_bytes = general_purpose::STANDARD.decode(base64_key)?;
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

pub struct Czdb {
    bindata: Mmap,
    index_blocks: BTreeMap<Vec<u8>, u32>,
    db_type: DbType,
    column_selection: u32,
    geo_map_data: Option<Vec<u8>>,
}

impl Czdb {
    pub fn new(db_path: &str, key: &str) -> Result<Self, CzError> {
        //初始化
        let key_bytes = general_purpose::STANDARD.decode(&key)?;
        let mut file = File::open(db_path)?;

        //读取头部
        let _version = file.read_u32::<LittleEndian>()?;
        let client_id = file.read_u32::<LittleEndian>()?;
        let encrypted_block_size = file.read_u32::<LittleEndian>()?;

        //读取并处理加密区域
        let mut encrypted_bytes = vec![0; encrypted_block_size as usize];
        file.read_exact(&mut encrypted_bytes)?;
        let cipher = Aes128::new(Key::<Aes128>::from_slice(&key_bytes));
        let mut decrypted_bytes = cipher
            .decrypt_padded_mut::<NoPadding>(&mut encrypted_bytes)
            .map_err(|_| CzError::DecryptionError)?;

        //校验参数是否匹配
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

        //留空长度
        let padding_size = decrypted_bytes.read_u32::<LittleEndian>()?;

        //读取剩余内容
        let mmap = unsafe {
            MmapOptions::new()
                .offset((12 + padding_size + encrypted_block_size) as u64)
                .map(&file)
        }?;
        let mut bindata = Cursor::new(mmap);

        //读取super part
        let db_type = if bindata.read_u8()? & 1 == 0 {
            DbType::Ipv4
        } else {
            DbType::Ipv6
        };
        let file_size = bindata.read_u32::<LittleEndian>()?;
        if file.metadata()?.len() != (padding_size + encrypted_block_size + 12 + file_size) as u64 {
            return Err(CzError::DatabaseFileCorrupted);
        }
        let start_index = bindata.read_u32::<LittleEndian>()?;
        let total_header_block_size = bindata.read_u32::<LittleEndian>()?;
        let end_index = bindata.read_u32::<LittleEndian>()?;
        let _total_index_blocks = (end_index - start_index) / db_type.index_block_len() as u32 + 1;

        //读取头部信息
        let total_header_block = total_header_block_size / 20;
        let mut buffer = [0; 20];
        let mut index_blocks = BTreeMap::new();
        for _ in 0..total_header_block {
            bindata.read_exact(&mut buffer)?;
            let ip = buffer[..16].to_vec();
            let data_ptr = u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);
            index_blocks.insert(ip, data_ptr);
        }

        //读取geo map
        let column_selection_ptr = end_index + db_type.index_block_len() as u32;
        bindata.seek(SeekFrom::Start(column_selection_ptr as u64))?;
        let column_selection = bindata.read_u32::<LittleEndian>()?;
        let mut geo_map_data = None;
        if column_selection != 0 {
            let geo_map_size = bindata.read_u32::<LittleEndian>()?;
            let mut buffer = vec![0; geo_map_size as usize];
            bindata.read_exact(&mut buffer)?;
            let data = GeoDataDecryptor::new(key)?.decrypt(&buffer);
            geo_map_data = Some(data);
        }

        Ok(Czdb {
            db_type,
            bindata: bindata.into_inner(),
            index_blocks,
            column_selection,
            geo_map_data,
        })
    }

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

        //开始二分查找
        let mut l = 0;
        let mut r = (end_ptr as usize - *start_ptr as usize) / block_len;
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
                // 提取数据长度和指针
                let data_len = ((geo_pos_mix_size >> 24) & 0xff) as usize; // 高 8 位为长度
                let data_ptr = (geo_pos_mix_size & 0x00ffffff) as usize; // 低 24 位为指针
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
            } else if start_ip > &ip_bytes {
                r = m - 1;
            } else {
                l = m + 1;
            }
        }

        None
    }
}
