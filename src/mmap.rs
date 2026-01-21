use crate::{
    CzError,
    common::{
        DbMeta, decode_aes_key, decode_region_from_bytes, parse_meta_from_bytes, read_hyper_header,
        compare_bytes,
    },
};
use memmap2::{Mmap, MmapOptions};
use std::{
    fs::File,
    net::IpAddr,
};

#[derive(Debug)]
struct MmapBytes {
    mmap: Mmap,
    offset: usize,
}

impl MmapBytes {
    fn as_slice(&self) -> &[u8] {
        &self.mmap[self.offset..]
    }
}

/// Mmap-backed CZDB searcher.
///
/// 基于 mmap 的 CZDB 查询器。
#[derive(Debug)]
pub struct CzdbMmap {
    bindata: MmapBytes,
    meta: DbMeta,
}

impl CzdbMmap {
    /// Open a database file using memory mapping.
    ///
    /// 使用内存映射打开数据库文件。
    pub fn open(db_path: &str, key: &str) -> Result<Self, CzError> {
        let key_bytes = decode_aes_key(key)?;
        let mut file = File::open(db_path)?;
        let header = read_hyper_header(&mut file, &key_bytes)?;
        let data_offset = (12 + header.padding_size + header.encrypted_block_size) as usize;
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        if data_offset > mmap.len() {
            return Err(CzError::DatabaseFileCorrupted);
        }
        let file_size_total = file.metadata()?.len();
        let bindata = MmapBytes { mmap, offset: data_offset };
        let meta = parse_meta_from_bytes(
            bindata.as_slice(),
            file_size_total,
            header.padding_size,
            header.encrypted_block_size,
            &key_bytes,
        )?;

        Ok(Self { bindata, meta })
    }

    /// Search a single IP address.
    ///
    /// 查询指定 IP 地址。
    pub fn search(&self, ip: IpAddr) -> Option<String> {
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

        let bindata = self.bindata.as_slice();
        let ip_len = self.meta.db_type.bytes_len();
        let blen = self.meta.db_type.index_block_len();
        let block_len = eptr - sptr;
        let max_len = sptr.saturating_add(block_len).saturating_add(blen);
        if max_len > bindata.len() {
            return None;
        }

        let mut l = 0usize;
        let mut h = block_len / blen;
        while l <= h {
            let m = (l + h) >> 1;
            let p = sptr + m * blen;
            let start_ip = &bindata[p..p + ip_len];
            let end_ip = &bindata[p + ip_len..p + ip_len * 2];
            let cmp_start = compare_bytes(&ip_bytes, start_ip, ip_len);
            let cmp_end = compare_bytes(&ip_bytes, end_ip, ip_len);

            if cmp_start != std::cmp::Ordering::Less && cmp_end != std::cmp::Ordering::Greater {
                let data_ptr = u32::from_le_bytes([
                    bindata[p + ip_len * 2],
                    bindata[p + ip_len * 2 + 1],
                    bindata[p + ip_len * 2 + 2],
                    bindata[p + ip_len * 2 + 3],
                ]) as usize;
                let data_len = bindata[p + ip_len * 2 + 4] as usize;
                if data_ptr + data_len > bindata.len() {
                    return None;
                }
                return decode_region_from_bytes(
                    &bindata[data_ptr..data_ptr + data_len],
                    &self.meta,
                );
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
    pub fn search_many(&self, ips: &[IpAddr]) -> Vec<Option<String>> {
        ips.iter().map(|ip| self.search(*ip)).collect()
    }
}
