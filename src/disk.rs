use crate::{
    CzError,
    common::{
        DbMeta, DbType, decode_aes_key, compare_bytes, decode_region_from_bytes, parse_meta_from_file,
        read_hyper_header,
    },
};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    net::IpAddr,
};

/// Disk-backed CZDB searcher.
///
/// 基于磁盘读取的 CZDB 查询器。
#[derive(Debug)]
pub struct CzdbDisk {
    file: File,
    data_offset: u64,
    meta: DbMeta,
}

impl CzdbDisk {
    /// Open a database file for disk-backed queries.
    ///
    /// 打开数据库文件用于磁盘查询。
    pub fn open(db_path: &str, key: &str) -> Result<Self, CzError> {
        let key_bytes = decode_aes_key(key)?;
        let mut file = File::open(db_path)?;
        let header = read_hyper_header(&mut file, &key_bytes)?;
        let data_offset = (12 + header.padding_size + header.encrypted_block_size) as u64;
        let file_size_total = file.metadata()?.len();
        let meta = parse_meta_from_file(
            &mut file,
            data_offset,
            file_size_total,
            header.padding_size,
            header.encrypted_block_size,
            &key_bytes,
        )?;

        Ok(Self {
            file,
            data_offset,
            meta,
        })
    }

    /// Search a single IP address.
    ///
    /// 查询指定 IP 地址。
    pub fn search(&mut self, ip: IpAddr) -> Option<String> {
        if !self.meta.db_type.compare(&ip) {
            return None;
        }
        let mut ip_bytes = [0u8; 16];
        match ip {
            IpAddr::V4(ip) => ip_bytes[..4].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => ip_bytes.copy_from_slice(&ip.octets()),
        }

        let (sptr, eptr) = self.meta.search_in_header(&ip_bytes)?;
        let sptr = sptr as usize;
        let eptr = eptr as usize;
        if eptr < sptr {
            return None;
        }

        let ip_len = self.meta.db_type.bytes_len();
        let blen = self.meta.db_type.index_block_len();
        let block_len = eptr - sptr;
        let read_len = block_len + blen;
        let mut index_buffer = vec![0u8; read_len];
        if self
            .file
            .seek(SeekFrom::Start(self.data_offset + sptr as u64))
            .is_err()
        {
            return None;
        }
        if self.file.read_exact(&mut index_buffer).is_err() {
            return None;
        }

        let mut l = 0usize;
        let mut h = block_len / blen;
        while l <= h {
            let m = (l + h) >> 1;
            let p = m * blen;
            let start_ip = &index_buffer[p..p + ip_len];
            let end_ip = &index_buffer[p + ip_len..p + ip_len * 2];
            let cmp_start = compare_bytes(&ip_bytes, start_ip, ip_len);
            let cmp_end = compare_bytes(&ip_bytes, end_ip, ip_len);

            if cmp_start != std::cmp::Ordering::Less && cmp_end != std::cmp::Ordering::Greater {
                let data_ptr = u32::from_le_bytes([
                    index_buffer[p + ip_len * 2],
                    index_buffer[p + ip_len * 2 + 1],
                    index_buffer[p + ip_len * 2 + 2],
                    index_buffer[p + ip_len * 2 + 3],
                ]) as usize;
                let data_len = index_buffer[p + ip_len * 2 + 4] as usize;
                if data_ptr == 0 || data_len == 0 {
                    return None;
                }
                let mut region_bytes = vec![0u8; data_len];
                if self
                    .file
                    .seek(SeekFrom::Start(self.data_offset + data_ptr as u64))
                    .is_err()
                {
                    return None;
                }
                if self.file.read_exact(&mut region_bytes).is_err() {
                    return None;
                }
                return decode_region_from_bytes(&region_bytes, &self.meta);
            } else if cmp_start == std::cmp::Ordering::Less {
                if m == 0 {
                    break;
                }
                h = m - 1;
            } else {
                l = m + 1;
            }
        }

        None
    }

    /// Search a small batch of IP addresses.
    ///
    /// 批量查询 IP（小批量）。
    pub fn search_many(&mut self, ips: &[IpAddr]) -> Vec<Option<String>> {
        ips.iter().map(|ip| self.search(*ip)).collect()
    }

    /// Returns the database IP version.
    ///
    /// 返回数据库类型（IPv4 或 IPv6）。
    pub fn db_type(&self) -> DbType {
        self.meta.db_type
    }
}
