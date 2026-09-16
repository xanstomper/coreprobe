// osleuth_core — CoreProbe native CLI.
//   hash   <file>...        SHA-256 (+ SHA-1) evidence hashes
//   verify <file> <hex>     check a file against an expected SHA-256
//   bench  [bytes]          hashing throughput benchmark
//   mbdb   <file>           parse Manifest.mbdb, flag traversal entries
//   selftest                run built-in unit tests
#include "core.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <tuple>
#include <string>
#include <vector>

using namespace coreprobe;

static int failures = 0;

static void check(bool cond, const char* what, const std::string& detail = "") {
    if (cond) {
        std::printf("  ok    %s\n", what);
    } else {
        std::printf("  FAIL  %s%s%s\n", what, detail.empty() ? "" : " :: ", detail.c_str());
        ++failures;
    }
}

static int cmd_selftest() {
    std::printf("osleuth_core selftest\n");

    Sha256 s;
    check(s.hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "sha256 empty", s.hex());
    s.reset();
    s.update("abc", 3);
    check(s.hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "sha256 abc", s.hex());
    s.reset();
    s.update("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
    check(s.hex() == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
          "sha256 56-byte block", s.hex());
    // Two-part update must equal one-shot (streaming correctness).
    s.reset();
    s.update("abc", 2);
    s.update("c", 1);
    check(s.hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "sha256 streaming");

    Sha1 s1;
    check(s1.hex() == "da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1 empty", s1.hex());
    s1.reset();
    s1.update("abc", 3);
    check(s1.hex() == "a9993e364706816aba3e25717850c26c9cd0d89d", "sha1 abc", s1.hex());

    // MBDB parse: header + one file record as produced by our verified
    // 26.6.1 writer (big-endian fields, count u16 BE, footer count+0xffffffff).
    auto mk_rec = [](const std::string& dom, const std::string& p) {
        std::string r;
        auto w16 = [&](uint16_t v) { r.push_back(char(v >> 8)); r.push_back(char(v)); };
        auto ws = [&](const std::string& s) { w16(uint16_t(s.size())); r += s; };
        auto w32 = [&](uint32_t v) { r.push_back(char(v >> 24)); r.push_back(char(v >> 16));
                                     r.push_back(char(v >> 8)); r.push_back(char(v)); };
        auto w64 = [&](uint64_t v) { w32(uint32_t(v >> 32)); w32(uint32_t(v)); };
        ws(dom); ws(p); ws("");
        static const unsigned char empty20[20] = {0};
        // datahash = SHA1 of path, like the Python writer
        Sha1 h; h.update(p.data(), p.size());
        std::string dh = h.hex();
        // hex string -> bytes (20)
        std::string dhb;
        for (size_t i = 0; i + 1 < dh.size(); i += 2) {
            auto nib = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
            dhb.push_back(char((nib(dh[i]) << 4) | nib(dh[i + 1])));
        }
        w16(uint16_t(dhb.size())); r += dhb;
        w16(20); r.append(reinterpret_cast<const char*>(empty20), 20);
        w16(0100644); w64(0); w32(501); w32(501);
        w32(100); w32(100); w32(100);
        w64(0); r.push_back(char(1)); r.push_back(char(0));
        return r;
    };
    std::string mbdb = "mbdb";
    mbdb.push_back(5); mbdb.push_back(0); mbdb.push_back(0); mbdb.push_back(0);  // u32 LE major
    mbdb.push_back(0); mbdb.push_back(2);                                        // u16 BE count
    mbdb += mk_rec("SystemContainerDomain-../../..", "Library/Preferences/x");
    mbdb += mk_rec("HomeDomain", "Media/DCIM/100APPLE/IMG_0001.JPG");
    mbdb.push_back(0); mbdb.push_back(0); mbdb.push_back(0); mbdb.push_back(2);  // u32 BE footer
    mbdb.push_back(char(0xff)); mbdb.push_back(char(0xff));
    mbdb.push_back(char(0xff)); mbdb.push_back(char(0xff));

    MbdbFile mf;
    std::string err;
    bool okp = parse_mbdb(reinterpret_cast<const uint8_t*>(mbdb.data()), mbdb.size(), mf, err);
    check(okp && err.empty(), "mbdb parse ok");
    check(mf.major == 5 && mf.count == 2 && mf.entries.size() == 2, "mbdb header fields");
    check(mf.entries[0].domain == "SystemContainerDomain-../../..", "mbdb domain");
    check(mf.entries[0].is_traversal(), "mbdb traversal detected (domain escape)");
    check(!mf.entries[1].is_traversal(), "mbdb normal path not flagged");
    check(mf.entries[1].is_file() && mf.entries[1].mode == 0100644, "mbdb mode/flag");
    check(mf.entries[1].uid == 501 && mf.entries[1].gid == 501, "mbdb uid/gid");
    check(mf.valid_bytes + 8 == mbdb.size(), "mbdb footer accounted");

    // Truncated input must fail gracefully (no OOB).
    MbdbFile bad;
    std::string berr;
    okp = parse_mbdb(reinterpret_cast<const uint8_t*>(mbdb.data()), 12, bad, berr);
    check(!okp && !berr.empty(), "mbdb truncated rejected");

    std::printf(failures ? "selftest FAILED (%d)\n" : "selftest PASSED\n", failures);
    return failures ? 1 : 0;
}

static int cmd_hash(const std::vector<std::string>& files, bool with_sha1) {
    for (const auto& f : files) {
        std::ifstream in(f, std::ios::binary);
        if (!in) { std::printf("unreadable: %s\n", f.c_str()); continue; }
        Sha256 h; Sha1 h1; char buf[1 << 16];
        while (in) { in.read(buf, sizeof buf); std::streamsize n = in.gcount();
                     if (n > 0) { h.update(buf, size_t(n)); h1.update(buf, size_t(n)); } }
        if (with_sha1) std::printf("SHA1   %s  %s\n", h1.hex().c_str(), f.c_str());
        std::printf("SHA256 %s  %s\n", h.hex().c_str(), f.c_str());
    }
    return 0;
}

static int cmd_verify(const std::string& file, const std::string& expect_hex) {
    bool ok = false;
    std::string s = sha256_file(file, ok);
    if (!ok) { std::printf("unreadable: %s\n", file.c_str()); return 2; }
    bool match = (s == expect_hex);
    std::printf("%s  %s\n", match ? "MATCH" : "MISMATCH", file.c_str());
    std::printf("expected %s\nactual   %s\n", expect_hex.c_str(), s.c_str());
    return match ? 0 : 1;
}

static int cmd_bench(uint64_t bytes) {
    std::vector<char> buf(1 << 20);
    for (auto& c : buf) c = char(size_t(&c));  // deterministic-ish fill
    Sha256 h;
    auto t0 = std::chrono::steady_clock::now();
    uint64_t done = 0;
    while (done + buf.size() <= bytes) {
        h.update(buf.data(), buf.size());
        done += buf.size();
    }
    auto t1 = std::chrono::steady_clock::now();
    double secs = std::chrono::duration<double>(t1 - t0).count();
    double mbps = (double(done) / (1 << 20)) / secs;
    std::printf("hashed %llu MiB in %.3fs -> %.1f MiB/s (sha256)\n",
                (unsigned long long)(done >> 20), secs, mbps);
    // SHA-1 throughput too
    Sha1 hs;
    t0 = std::chrono::steady_clock::now();
    done = 0;
    while (done + buf.size() <= bytes) { hs.update(buf.data(), buf.size()); done += buf.size(); }
    t1 = std::chrono::steady_clock::now();
    secs = std::chrono::duration<double>(t1 - t0).count();
    mbps = (double(done) / (1 << 20)) / secs;
    std::printf("hashed %llu MiB in %.3fs -> %.1f MiB/s (sha1)\n",
                (unsigned long long)(done >> 20), secs, mbps);
    return 0;
}

static int cmd_manifest(const std::string& dir) {
    std::error_code ec;
    std::filesystem::recursive_directory_iterator it(
        std::filesystem::path(dir), std::filesystem::directory_options::skip_permission_denied, ec);
    std::filesystem::recursive_directory_iterator end;
    std::vector<std::tuple<std::string, uint64_t, std::string>> rows;
    for (; !ec && it != end; it.increment(ec)) {
        const auto& p = it->path();
        if (!it->is_regular_file(ec) || ec) continue;
        std::string rel = std::filesystem::relative(p, dir, ec).generic_string();
        uint64_t sz = it->file_size(ec);
        bool ok = false;
        std::string h = sha256_file(p.string(), ok);
        if (!ok) { std::printf("unreadable: %s\n", p.string().c_str()); continue; }
        rows.emplace_back(h, sz, rel);
    }
    std::sort(rows.begin(), rows.end(),
              [](const auto& a, const auto& b) { return std::get<2>(a) < std::get<2>(b); });
    std::printf("# osleuth_core manifest: %s (%zu files)\n", dir.c_str(), rows.size());
    for (const auto& [h, sz, rel] : rows)
        std::printf("%s  %llu  %s\n", h.c_str(), (unsigned long long)sz, rel.c_str());
    if (ec) { std::printf("# walk stopped early: %s\n", ec.message().c_str()); return 1; }
    return 0;
}

static int cmd_mbdb(const std::string& file) {
    std::ifstream in(file, std::ios::binary);
    if (!in) { std::printf("unreadable: %s\n", file.c_str()); return 2; }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
    MbdbFile mf;
    std::string err;
    if (!parse_mbdb(data.data(), data.size(), mf, err)) {
        std::printf("parse error at byte %zu: %s\n", mf.valid_bytes, err.c_str());
        return 1;
    }
    std::printf("major=%u count=%u valid_bytes=%zu\n", mf.major, mf.count, mf.valid_bytes);
    size_t trav = 0;
    for (size_t i = 0; i < mf.entries.size(); ++i) {
        const auto& e = mf.entries[i];
        std::printf("%4zu  %s  %s%s  uid=%u gid=%u size=%llu mode=%04o\n",
                    i, e.domain.c_str(), e.path.c_str(), e.is_traversal() ? "  <TRAVERSAL>" : "",
                    e.uid, e.gid, (unsigned long long)e.size, e.mode);
        if (e.is_traversal()) ++trav;
    }
    std::printf("traversal entries: %zu\n", trav);
    return 0;
}

static void usage() {
    std::printf(
        "osleuth_core - CoreProbe native core\n"
        "usage:\n"
        "  osleuth_core hash [--sha1] <file>...\n"
        "  osleuth_core verify <file> <expected-sha256-hex>\n"
        "  osleuth_core bench [bytes=1GiB]\n"
        "  osleuth_core mbdb <Manifest.mbdb>\n"
        "  osleuth_core manifest <dir>\n"
        "  osleuth_core selftest\n");
}

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) { usage(); return 2; }
    const std::string& cmd = args[0];
    if (cmd == "selftest") return cmd_selftest();
    if (cmd == "hash") {
        bool sha1 = false;
        std::vector<std::string> files;
        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--sha1") sha1 = true;
            else files.push_back(args[i]);
        }
        if (files.empty()) { usage(); return 2; }
        return cmd_hash(files, sha1);
    }
    if (cmd == "verify") {
        if (args.size() != 3) { usage(); return 2; }
        return cmd_verify(args[1], args[2]);
    }
    if (cmd == "bench") {
        uint64_t bytes = 1ull << 30;
        if (args.size() >= 2) {
            try { bytes = std::stoull(args[1]); } catch (...) { usage(); return 2; }
        }
        return cmd_bench(bytes);
    }
    if (cmd == "mbdb") {
        if (args.size() != 2) { usage(); return 2; }
        return cmd_mbdb(args[1]);
    }
    if (cmd == "manifest") {
        if (args.size() != 2) { usage(); return 2; }
        return cmd_manifest(args[1]);
    }
    usage();
    return 2;
}