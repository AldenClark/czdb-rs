use crate::{
    CzError,
    common::{
        DbMeta, DbType, decode_aes_key, decode_region_from_bytes, parse_meta_from_bytes,
        read_hyper_header, compare_bytes,
    },
};
use std::{
    collections::HashMap,
    fs::File,
    io::{Cursor, Read},
    net::IpAddr,
};

#[derive(Debug)]
struct MemoryIndex {
    entries_v4: Vec<IndexEntryV4>,
    entries_v6: Vec<IndexEntryV6>,
    regions: RegionPool,
}

#[derive(Debug)]
struct IndexEntryV4 {
    start_ip: u32,
    end_ip: u32,
    region_id: usize,
}

#[derive(Debug)]
struct IndexEntryV6 {
    start_ip: [u8; 16],
    end_ip: [u8; 16],
    region_id: usize,
}

#[derive(Debug)]
struct RegionSpan {
    start: usize,
    len: usize,
}

#[derive(Debug)]
struct RegionPool {
    data: Box<str>,
    spans: Vec<RegionSpan>,
}

impl RegionPool {
    fn get(&self, region_id: usize) -> &str {
        let span = &self.spans[region_id];
        &self.data[span.start..span.start + span.len]
    }
}

/// In-memory CZDB searcher with a prebuilt index and string pool.
///
/// 预构建索引与字符串池的内存 CZDB 查询器。
#[derive(Debug)]
pub struct CzdbMemory {
    meta: DbMeta,
    memory_index: MemoryIndex,
}

impl CzdbMemory {
    /// Open a database file and build in-memory indices.
    ///
    /// 打开数据库文件并构建内存索引。
    pub fn open(db_path: &str, key: &str) -> Result<Self, CzError> {
        let mut file = File::open(db_path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Self::from_bytes(data, key)
    }

    /// Build from raw bytes and construct in-memory indices.
    ///
    /// 从原始字节构建并生成内存索引。
    pub fn from_bytes(data: Vec<u8>, key: &str) -> Result<Self, CzError> {
        let key_bytes = decode_aes_key(key)?;
        let mut cursor = Cursor::new(&data);
        let header = read_hyper_header(&mut cursor, &key_bytes)?;
        let data_offset = (12 + header.padding_size + header.encrypted_block_size) as usize;
        if data_offset > data.len() {
            return Err(CzError::DatabaseFileCorrupted);
        }
        let file_size_total = data.len() as u64;
        let meta = parse_meta_from_bytes(
            &data[data_offset..],
            file_size_total,
            header.padding_size,
            header.encrypted_block_size,
            &key_bytes,
        )?;
        let memory_index = build_memory_index(&data[data_offset..], &meta)?;

        Ok(Self {
            meta,
            memory_index,
        })
    }

    /// Search a single IP address.
    ///
    /// 查询指定 IP 地址。
    pub fn search(&self, ip: IpAddr) -> Option<String> {
        self.search_ref(ip).map(str::to_string)
    }

    /// Search a single IP address and return a borrowed string.
    ///
    /// 查询指定 IP 并返回借用字符串。
    pub fn search_ref(&self, ip: IpAddr) -> Option<&str> {
        if !self.meta.db_type.compare(&ip) {
            return None;
        }
        match ip {
            IpAddr::V4(ip) => {
                if self.memory_index.entries_v4.is_empty() {
                    return None;
                }
                let ip_num = u32::from_be_bytes(ip.octets());
                let mut l = 0usize;
                let mut h = self.memory_index.entries_v4.len() - 1;
                while l <= h {
                    let m = (l + h) >> 1;
                    let entry = &self.memory_index.entries_v4[m];
                    if ip_num >= entry.start_ip && ip_num <= entry.end_ip {
                        return Some(self.memory_index.regions.get(entry.region_id));
                    } else if ip_num < entry.start_ip {
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
            IpAddr::V6(ip) => {
                if self.memory_index.entries_v6.is_empty() {
                    return None;
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&ip.octets());
                let mut l = 0usize;
                let mut h = self.memory_index.entries_v6.len() - 1;
                while l <= h {
                    let m = (l + h) >> 1;
                    let entry = &self.memory_index.entries_v6[m];
                    let cmp_start = compare_bytes(&ip_bytes, &entry.start_ip, 16);
                    let cmp_end = compare_bytes(&ip_bytes, &entry.end_ip, 16);
                    if cmp_start != std::cmp::Ordering::Less
                        && cmp_end != std::cmp::Ordering::Greater
                    {
                        return Some(self.memory_index.regions.get(entry.region_id));
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
        }
    }

    /// Search a small batch of IP addresses.
    ///
    /// 批量查询 IP（小批量）。
    pub fn search_many(&self, ips: &[IpAddr]) -> Vec<Option<String>> {
        ips.iter().map(|ip| self.search(*ip)).collect()
    }

    /// Search a batch of IP addresses and return borrowed strings.
    ///
    /// 批量查询 IP 并返回借用字符串。
    pub fn search_many_ref<'a>(&'a self, ips: &[IpAddr]) -> Vec<Option<&'a str>> {
        ips.iter().map(|ip| self.search_ref(*ip)).collect()
    }

    /// Search a large batch by sorting and scanning.
    ///
    /// 对大批量 IP 进行排序后扫描查询。
    pub fn search_many_scan<'a>(&'a self, ips: &[IpAddr]) -> Vec<Option<&'a str>> {
        let mut results = vec![None; ips.len()];
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for (idx, ip) in ips.iter().copied().enumerate() {
            match ip {
                IpAddr::V4(ipv4) => v4.push((u32::from_be_bytes(ipv4.octets()), idx)),
                IpAddr::V6(ipv6) => v6.push((ipv6.octets(), idx)),
            }
        }

        if !v4.is_empty() && !self.memory_index.entries_v4.is_empty() {
            v4.sort_unstable_by_key(|(ip, _)| *ip);
            let mut entry_idx = 0usize;
            for (ip_num, original_idx) in v4 {
                while entry_idx < self.memory_index.entries_v4.len()
                    && self.memory_index.entries_v4[entry_idx].end_ip < ip_num
                {
                    entry_idx += 1;
                }
                if entry_idx >= self.memory_index.entries_v4.len() {
                    break;
                }
                let entry = &self.memory_index.entries_v4[entry_idx];
                if ip_num >= entry.start_ip && ip_num <= entry.end_ip {
                    results[original_idx] = Some(self.memory_index.regions.get(entry.region_id));
                }
            }
        }

        if !v6.is_empty() && !self.memory_index.entries_v6.is_empty() {
            v6.sort_unstable_by(|(a, _), (b, _)| compare_bytes(a, b, 16));
            let mut entry_idx = 0usize;
            for (ip_bytes, original_idx) in v6 {
                while entry_idx < self.memory_index.entries_v6.len()
                    && compare_bytes(&self.memory_index.entries_v6[entry_idx].end_ip, &ip_bytes, 16)
                        == std::cmp::Ordering::Less
                {
                    entry_idx += 1;
                }
                if entry_idx >= self.memory_index.entries_v6.len() {
                    break;
                }
                let entry = &self.memory_index.entries_v6[entry_idx];
                let cmp_start = compare_bytes(&ip_bytes, &entry.start_ip, 16);
                let cmp_end = compare_bytes(&ip_bytes, &entry.end_ip, 16);
                if cmp_start != std::cmp::Ordering::Less
                    && cmp_end != std::cmp::Ordering::Greater
                {
                    results[original_idx] = Some(self.memory_index.regions.get(entry.region_id));
                }
            }
        }

        results
    }

    /// Returns the database IP version.
    ///
    /// 返回数据库类型（IPv4 或 IPv6）。
    pub fn db_type(&self) -> DbType {
        self.meta.db_type
    }
}

fn build_memory_index(bindata: &[u8], meta: &DbMeta) -> Result<MemoryIndex, CzError> {
    let ip_len = meta.db_type.bytes_len();
    let blen = meta.db_type.index_block_len();
    let start = meta.start_index as usize;
    let end = meta.end_index as usize;

    if end < start {
        return Err(CzError::DatabaseFileCorrupted);
    }
    if end + blen > bindata.len() {
        return Err(CzError::DatabaseFileCorrupted);
    }

    let total_blocks = (end - start) / blen + 1;
    let mut entries_v4 = Vec::with_capacity(total_blocks);
    let mut entries_v6 = Vec::with_capacity(total_blocks);
    let mut regions = Vec::<RegionSpan>::new();
    let mut region_text = String::new();
    let mut region_cache = HashMap::<(usize, usize), usize>::new();

    let mut p = start;
    while p <= end {
        if p + blen > bindata.len() {
            return Err(CzError::DatabaseFileCorrupted);
        }
        let mut start_ip_bytes = [0u8; 16];
        let mut end_ip_bytes = [0u8; 16];
        start_ip_bytes[..ip_len].copy_from_slice(&bindata[p..p + ip_len]);
        end_ip_bytes[..ip_len].copy_from_slice(&bindata[p + ip_len..p + ip_len * 2]);
        let data_ptr = u32::from_le_bytes([
            bindata[p + ip_len * 2],
            bindata[p + ip_len * 2 + 1],
            bindata[p + ip_len * 2 + 2],
            bindata[p + ip_len * 2 + 3],
        ]) as usize;
        let data_len = bindata[p + ip_len * 2 + 4] as usize;

        let region_id = match region_cache.get(&(data_ptr, data_len)) {
            Some(id) => *id,
            None => {
                if data_ptr + data_len > bindata.len() {
                    return Err(CzError::DatabaseFileCorrupted);
                }
                let region = decode_region_from_bytes(
                    &bindata[data_ptr..data_ptr + data_len],
                    meta,
                )
                .ok_or(CzError::DatabaseFileCorrupted)?;
                let start_offset = region_text.len();
                region_text.push_str(&region);
                let len = region.len();
                let id = regions.len();
                regions.push(RegionSpan {
                    start: start_offset,
                    len,
                });
                region_cache.insert((data_ptr, data_len), id);
                id
            }
        };

        if meta.db_type == DbType::Ipv4 {
            let start_ip = u32::from_be_bytes(start_ip_bytes[..4].try_into().unwrap());
            let end_ip = u32::from_be_bytes(end_ip_bytes[..4].try_into().unwrap());
            entries_v4.push(IndexEntryV4 {
                start_ip,
                end_ip,
                region_id,
            });
        } else {
            entries_v6.push(IndexEntryV6 {
                start_ip: start_ip_bytes,
                end_ip: end_ip_bytes,
                region_id,
            });
        }

        p += blen;
    }

    Ok(MemoryIndex {
        entries_v4,
        entries_v6,
        regions: RegionPool {
            data: region_text.into_boxed_str(),
            spans: regions,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmpv::{Value, encode::write_value};
    use std::net::Ipv4Addr;

    fn build_test_db() -> CzdbMemory {
        let block_len = DbType::Ipv4.index_block_len();
        let padding = 4usize;
        let mut bindata = vec![0u8; padding + block_len * 2];

        let mut region1 = Vec::new();
        write_value(&mut region1, &Value::Integer(0.into())).unwrap();
        write_value(&mut region1, &Value::String("region1".into())).unwrap();

        let mut region2 = Vec::new();
        write_value(&mut region2, &Value::Integer(0.into())).unwrap();
        write_value(&mut region2, &Value::String("region2".into())).unwrap();

        let region1_ptr = (padding + block_len * 2) as u32;
        let region2_ptr = region1_ptr + region1.len() as u32;

        let first_offset = padding;
        bindata[first_offset..first_offset + 4].copy_from_slice(&[1, 1, 1, 0]);
        bindata[first_offset + 4..first_offset + 8].copy_from_slice(&[1, 1, 1, 255]);
        bindata[first_offset + 8..first_offset + 12].copy_from_slice(&region1_ptr.to_le_bytes());
        bindata[first_offset + 12] = region1.len() as u8;

        let offset = padding + block_len;
        bindata[offset..offset + 4].copy_from_slice(&[2, 2, 2, 0]);
        bindata[offset + 4..offset + 8].copy_from_slice(&[2, 2, 2, 255]);
        bindata[offset + 8..offset + 12].copy_from_slice(&region2_ptr.to_le_bytes());
        bindata[offset + 12] = region2.len() as u8;

        bindata.extend_from_slice(&region1);
        bindata.extend_from_slice(&region2);

        let mut header_sip = Vec::new();
        let mut header_ptr = Vec::new();
        let mut ip1 = [0u8; 16];
        let mut ip2 = [0u8; 16];
        ip1[..4].copy_from_slice(&[1, 1, 1, 0]);
        ip2[..4].copy_from_slice(&[2, 2, 2, 0]);
        header_sip.push(ip1);
        header_sip.push(ip2);
        header_ptr.push(first_offset as u32);
        header_ptr.push(offset as u32);

        let meta = DbMeta {
            db_type: DbType::Ipv4,
            header_sip,
            header_ptr,
            column_selection: 0,
            geo_map_data: None,
            start_index: first_offset as u32,
            end_index: offset as u32,
        };

        let memory_index = build_memory_index(&bindata, &meta).unwrap();

        let _ = bindata;
        CzdbMemory { meta, memory_index }
    }

    #[test]
    fn search_handles_start_boundary_correctly() {
        let db = build_test_db();
        assert_eq!(
            db.search(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 0))),
            Some("region1".to_string())
        );
    }

    #[test]
    fn search_returns_expected_results() {
        let db = build_test_db();
        assert_eq!(
            db.search(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))),
            Some("region2".to_string())
        );
        assert!(db.search(IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))).is_none());
    }
}
