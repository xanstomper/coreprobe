// CoreProbe native core — self-contained C++17, zero external deps.
// SHA-256 / SHA-1 / MBDB parser / traversal detection / benchmarks.
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace coreprobe {

// ---------------------------------------------------------------- sha256 --
class Sha256 {
public:
    Sha256() { reset(); }
    void reset();
    void update(const void* data, size_t len);
    void final(uint8_t out[32]);
    std::string hex();  // calls final internally into cached digest
private:
    uint32_t h_[8];
    uint8_t block_[64];
    size_t block_len_ = 0;
    uint64_t total_ = 0;   // bytes
    uint8_t digest_[32];
    bool done_ = false;
    void transform(const uint8_t block[64]);
};

// ----------------------------------------------------------------- sha1 --
class Sha1 {
public:
    Sha1() { reset(); }
    void reset();
    void update(const void* data, size_t len);
    void final(uint8_t out[20]);
    std::string hex();
private:
    uint32_t h_[5];
    uint8_t block_[64];
    size_t block_len_ = 0;
    uint64_t total_ = 0;
    uint8_t digest_[20];
    bool done_ = false;
    void transform(const uint8_t block[64]);
};

// ---------------------------------------------------------------- mbdb --
// Manifest.mbdb binary record (format reverse-engineered against iOS 26.6.1,
// see docs/research-2026-09-16-afc-26.6.1.md). Header: "mbdb" + u32 LE major
// + u16 BE count. Records: big-endian length-prefixed fields. Trailing:
// u32 BE count + 0xffffffff.
struct MbdbEntry {
    std::string domain;
    std::string path;
    std::string linktarget;
    std::vector<uint8_t> datahash;   // SHA-1 of path content
    std::vector<uint8_t> unknown1;   // 20 bytes
    uint16_t mode = 0;
    uint64_t inode = 0;
    uint32_t uid = 0;
    uint32_t gid = 0;
    uint32_t mtime = 0;
    uint32_t atime = 0;
    uint32_t ctime = 0;
    uint64_t size = 0;
    uint8_t flag = 0;
    std::vector<std::pair<std::string, std::string>> properties;

    bool is_symlink() const { return (mode & 0170000) == 0120000; }
    bool is_dir() const { return (mode & 0170000) == 0040000; }
    bool is_file() const { return (mode & 0170000) == 0100000; }
    // Path escapes the backup sandbox (dot-dot traversal, the CVE-2026-84598
    // shape) or carries an absolute / domain-escape prefix.
    bool is_traversal() const;
};

struct MbdbFile {
    uint32_t major = 0;
    uint16_t count = 0;
    std::vector<MbdbEntry> entries;
    // Byte offset at which parsing stopped (valid record stream length).
    size_t valid_bytes = 0;
};

// Returns ok=false + error message on malformed data. Trailing garbage is
// allowed (footer) and reported in valid_bytes.
bool parse_mbdb(const uint8_t* data, size_t len, MbdbFile& out, std::string& err);

// ------------------------------------------------------------- utilities --
std::string hex_encode(const uint8_t* data, size_t len);
std::string sha256_file(const std::string& path, bool& ok);
std::string sha1_file(const std::string& path, bool& ok);

}  // namespace coreprobe