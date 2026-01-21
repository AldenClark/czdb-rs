## v0.2.0

- Split APIs into `CzdbDisk`, `CzdbMmap`, and `CzdbMemory` for clearer mode separation.
- Add memory-only fast path with prebuilt indices, string pool, and batch scan method.
- Make memory mode available by default; keep mmap behind feature flag.
- Standardize header parsing and search behavior to align with official references.
- Update docs/README to bilingual single file and expand usage guidance.

- 拆分为 `CzdbDisk`/`CzdbMmap`/`CzdbMemory`，按模式提供更清晰的 API。
- 新增内存加速路径，预构建索引与字符串池，并提供批量扫描方法。
- 内存模式默认可用；mmap 仍通过 feature 开启。
- 对齐官方参考实现的头部解析与查询行为。
- README 与文档改为单文件双语说明并完善用法。

## v0.1.4

- Fix index range calculation in `search` to avoid out-of-bounds access.
- Add unit tests covering boundary IP lookups.
- Add Chinese README and documentation updates.

- 修复 `search` 的索引范围计算，避免越界访问。
- 新增边界 IP 查询的单元测试。
- 新增中文 README 并更新文档。

## v0.1.3

- Add multiple readers: standard `BufReader`, optional `mmap` feature, and in-memory loading.

- 新增多种读取方式：`BufReader`、可选 `mmap`，以及内存加载。

## v0.1.2

- Fix a binary search indexing bug in `search`.

- 修复 `search` 中的二分索引错误。

## v0.1.1

- Fix several bugs to improve stability.
- Enhance documentation with clearer examples and feature descriptions.

- 修复多处问题以提升稳定性。
- 完善文档示例与功能说明。

## v0.1.0 - Initial Release

- First release of czdb-rs.
- Support parsing CZDB-format IP databases.
- Support both IPv4 and IPv6 lookups.
- Optimize memory usage and disk access with memory-mapped files (mmap).
- Requires database file and key from www.cz88.net.

- czdb-rs 首次发布。
- 支持解析 CZDB 格式数据库。
- 支持 IPv4 与 IPv6 查询。
- 通过 mmap 优化内存与磁盘访问。
- 数据库文件与密钥需从 www.cz88.net 获取。
