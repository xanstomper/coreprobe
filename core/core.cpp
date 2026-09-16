// CoreProbe native core implementation.
#include "core.h"

#include <cstdio>
#include <cstring>
#include <fstream>

namespace coreprobe {

// ================================================================ sha256 ==
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void Sha256::reset() {
    h_[0] = 0x6a09e667; h_[1] = 0xbb67ae85; h_[2] = 0x3c6ef372; h_[3] = 0xa54ff53a;
    h_[4] = 0x510e527f; h_[5] = 0x9b05688c; h_[6] = 0x1f83d9ab; h_[7] = 0x5be0cd19;
    block_len_ = 0; total_ = 0; done_ = false;
}

void Sha256::transform(const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t(block[i*4]) << 24) | (uint32_t(block[i*4+1]) << 16) |
               (uint32_t(block[i*4+2]) << 8) | uint32_t(block[i*4+3]);
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
    h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
}

void Sha256::update(const void* data, size_t len) {
    if (done_) { reset(); }
    const uint8_t* p = static_cast<const uint8_t*>(data);
    total_ += len;
    if (block_len_ > 0) {
        size_t need = 64 - block_len_;
        size_t take = len < need ? len : need;
        memcpy(block_ + block_len_, p, take);
        block_len_ += take; p += take; len -= take;
        if (block_len_ == 64) { transform(block_); block_len_ = 0; }
    }
    while (len >= 64) { transform(p); p += 64; len -= 64; }
    if (len > 0) { memcpy(block_, p, len); block_len_ = len; }
}

void Sha256::final(uint8_t out[32]) {
    if (done_) { memcpy(out, digest_, 32); return; }
    uint64_t bits = total_ * 8;
    uint8_t pad = 0x80;
    update(&pad, 1);
    uint8_t zero = 0;
    while (block_len_ != 56) update(&zero, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; ++i) lenb[i] = uint8_t(bits >> (56 - 8 * i));
    update(lenb, 8);
    for (int i = 0; i < 8; ++i) {
        digest_[i*4]   = uint8_t(h_[i] >> 24);
        digest_[i*4+1] = uint8_t(h_[i] >> 16);
        digest_[i*4+2] = uint8_t(h_[i] >> 8);
        digest_[i*4+3] = uint8_t(h_[i]);
    }
    done_ = true;
    memcpy(out, digest_, 32);
}

std::string Sha256::hex() {
    uint8_t d[32];
    final(d);
    return hex_encode(d, 32);
}

// ================================================================= sha1 ==
static const uint32_t K1[4] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};

static inline uint32_t rol32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void Sha1::reset() {
    h_[0] = 0x67452301; h_[1] = 0xefcdab89; h_[2] = 0x98badcfe;
    h_[3] = 0x10325476; h_[4] = 0xc3d2e1f0;
    block_len_ = 0; total_ = 0; done_ = false;
}

void Sha1::transform(const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t(block[i*4]) << 24) | (uint32_t(block[i*4+1]) << 16) |
               (uint32_t(block[i*4+2]) << 8) | uint32_t(block[i*4+3]);
    for (int i = 16; i < 80; ++i)
        w[i] = rol32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d);     k = K1[0]; }
        else if (i < 40) { f = b ^ c ^ d;              k = K1[1]; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = K1[2]; }
        else             { f = b ^ c ^ d;              k = K1[3]; }
        uint32_t tmp = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = tmp;
    }
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e;
}

void Sha1::update(const void* data, size_t len) {
    if (done_) { reset(); }
    const uint8_t* p = static_cast<const uint8_t*>(data);
    total_ += len;
    if (block_len_ > 0) {
        size_t need = 64 - block_len_;
        size_t take = len < need ? len : need;
        memcpy(block_ + block_len_, p, take);
        block_len_ += take; p += take; len -= take;
        if (block_len_ == 64) { transform(block_); block_len_ = 0; }
    }
    while (len >= 64) { transform(p); p += 64; len -= 64; }
    if (len > 0) { memcpy(block_, p, len); block_len_ = len; }
}

void Sha1::final(uint8_t out[20]) {
    if (done_) { memcpy(out, digest_, 20); return; }
    uint64_t bits = total_ * 8;
    uint8_t pad = 0x80;
    update(&pad, 1);
    uint8_t zero = 0;
    while (block_len_ != 56) update(&zero, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; ++i) lenb[i] = uint8_t(bits >> (56 - 8 * i));
    update(lenb, 8);
    for (int i = 0; i < 5; ++i) {
        digest_[i*4]   = uint8_t(h_[i] >> 24);
        digest_[i*4+1] = uint8_t(h_[i] >> 16);
        digest_[i*4+2] = uint8_t(h_[i] >> 8);
        digest_[i*4+3] = uint8_t(h_[i]);
    }
    done_ = true;
    memcpy(out, digest_, 20);
}

std::string Sha1::hex() {
    uint8_t d[20];
    final(d);
    return hex_encode(d, 20);
}

// ================================================================= mbdb ==
static bool read_u16(const uint8_t* p, size_t len, size_t& off, uint16_t& out) {
    if (off + 2 > len) return false;
    out = uint16_t((uint16_t(p[off]) << 8) | p[off + 1]);
    off += 2;
    return true;
}
static bool read_u32(const uint8_t* p, size_t len, size_t& off, uint32_t& out) {
    if (off + 4 > len) return false;
    out = (uint32_t(p[off]) << 24) | (uint32_t(p[off+1]) << 16) |
          (uint32_t(p[off+2]) << 8) | uint32_t(p[off+3]);
    off += 4;
    return true;
}
static bool read_u64(const uint8_t* p, size_t len, size_t& off, uint64_t& out) {
    uint32_t hi, lo;
    if (!read_u32(p, len, off, hi) || !read_u32(p, len, off, lo)) return false;
    out = (uint64_t(hi) << 32) | lo;
    return true;
}
static bool read_bytes(const uint8_t* p, size_t len, size_t& off,
                       std::vector<uint8_t>& out) {
    uint16_t n;
    if (!read_u16(p, len, off, n) || off + n > len) return false;
    out.assign(p + off, p + off + n);
    off += n;
    return true;
}
static bool read_string(const uint8_t* p, size_t len, size_t& off, std::string& out) {
    std::vector<uint8_t> b;
    if (!read_bytes(p, len, off, b)) return false;
    out.assign(b.begin(), b.end());
    return true;
}

bool MbdbEntry::is_traversal() const {
    // Dot-dot escapes and sandbox/domain escapes seen in crafted backups
    // (../../Media, /var/tmp deep paths, SysContainerDomain-../../..). Both
    // the path AND the domain field can carry the escape.
    auto check = [](const std::string& t) {
        if (t.rfind("..", 0) == 0) return true;                       // ../../Media
        if (t.find("/../") != std::string::npos) return true;         // a/../b
        if (t.size() >= 3 && t.compare(t.size() - 3, 3, "/..") == 0) return true;
        if (!t.empty() && t[0] == '/') return true;                   // /var/tmp (absolute)
        size_t pos = 0;
        while ((pos = t.find("..", pos)) != std::string::npos) {
            bool prev_ok = pos == 0 || t[pos - 1] == '/' || t[pos - 1] == '-';
            bool next_ok = pos + 2 >= t.size() || t[pos + 2] == '/' || t[pos + 2] == '-';
            if (prev_ok && next_ok) return true;                      // Domain-../../..
            pos += 2;
        }
        return false;
    };
    return check(path) || check(domain) || check(linktarget);
}

bool parse_mbdb(const uint8_t* data, size_t len, MbdbFile& out, std::string& err) {
    out = MbdbFile{};
    if (len < 10 || memcmp(data, "mbdb", 4) != 0) {
        err = "not an mbdb (missing magic)";
        return false;
    }
    out.major = uint32_t(data[4]) | (uint32_t(data[5]) << 8) |
                (uint32_t(data[6]) << 16) | (uint32_t(data[7]) << 24);
    out.count = uint16_t((uint16_t(data[8]) << 8) | data[9]);
    size_t off = 10;
    for (uint16_t i = 0; i < out.count; ++i) {
        MbdbEntry e;
        if (!read_string(data, len, off, e.domain) ||
            !read_string(data, len, off, e.path) ||
            !read_string(data, len, off, e.linktarget) ||
            !read_bytes(data, len, off, e.datahash) ||
            !read_bytes(data, len, off, e.unknown1) ||
            !read_u16(data, len, off, e.mode) ||
            !read_u64(data, len, off, e.inode) ||
            !read_u32(data, len, off, e.uid) ||
            !read_u32(data, len, off, e.gid) ||
            !read_u32(data, len, off, e.mtime) ||
            !read_u32(data, len, off, e.atime) ||
            !read_u32(data, len, off, e.ctime) ||
            !read_u64(data, len, off, e.size)) {
            err = "record " + std::to_string(i) + ": truncated";
            out.valid_bytes = off;
            return false;
        }
        if (off >= len) { err = "record " + std::to_string(i) + ": no flag byte"; return false; }
        e.flag = data[off++];
        if (off >= len) { err = "record " + std::to_string(i) + ": no property count"; return false; }
        uint8_t nprops = data[off++];
        for (uint8_t p = 0; p < nprops; ++p) {
            std::string pn, pv;
            if (!read_string(data, len, off, pn) || !read_string(data, len, off, pv)) {
                err = "record " + std::to_string(i) + ": bad property " + std::to_string(p);
                out.valid_bytes = off;
                return false;
            }
            e.properties.emplace_back(pn, pv);
        }
        out.entries.push_back(std::move(e));
    }
    out.valid_bytes = off;
    return true;
}

// ============================================================ utilities ==
std::string hex_encode(const uint8_t* data, size_t len) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        s.push_back(H[data[i] >> 4]);
        s.push_back(H[data[i] & 0xf]);
    }
    return s;
}

static std::string hash_file(const std::string& path, bool& ok,
                             std::string* sha1_out = nullptr) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { ok = false; return "unreadable"; }
    Sha256 s256;
    Sha1 s1;
    char buf[1 << 16];
    while (f) {
        f.read(buf, sizeof buf);
        std::streamsize n = f.gcount();
        if (n > 0) {
            s256.update(buf, size_t(n));
            s1.update(buf, size_t(n));
        }
    }
    ok = !f.bad();
    if (sha1_out) *sha1_out = s1.hex();
    return s256.hex();
}

std::string sha256_file(const std::string& path, bool& ok) { return hash_file(path, ok); }
std::string sha1_file(const std::string& path, bool& ok) {
    std::string s1;
    hash_file(path, ok, &s1);
    return s1;
}

}  // namespace coreprobe