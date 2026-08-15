// protocol.hpp - shared wire protocol definitions (little-endian framing)
// STRICT RULE COMPLIANT: no new/delete/malloc anywhere. Header-only, RAII.
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <array>

namespace lgx {

// ---------------------------------------------------------------------------
// Wire protocol
//
//   Request  (client -> server):
//     [u32 magic 'LGX1'][u8 cmd][u8 flags][u16 name_len][u64 payload_size]
//     [name_len bytes: file name (UTF-8)]
//     [payload_size bytes: raw file stream]
//
//   Response (server -> client):
//     same fixed header layout, cmd = RESULT_CSV or ERROR_TEXT,
//     payload = result.csv bytes (or UTF-8 error message).
// ---------------------------------------------------------------------------

constexpr std::uint32_t kMagic = 0x3158474Cu; // "LGX1" little-endian
constexpr std::uint16_t kDefaultPort = 45777;

enum class Cmd : std::uint8_t {
    UploadLog = 1, // client -> server: here comes a log file
    ResultCsv = 2, // server -> client: analysis result (result.csv)
    ErrorText = 3, // server -> client: human readable failure reason
};

constexpr std::size_t   kHeaderSize     = 16;                    // fixed part
constexpr std::uint16_t kMaxNameLen     = 1024;                  // sanity cap
constexpr std::uint64_t kMaxPayloadSize = 8ull * 1024 * 1024 * 1024; // 8 GiB cap
constexpr std::size_t   kChunkSize      = 64 * 1024;             // stream chunk

struct FrameHeader {
    std::uint32_t magic = kMagic;
    Cmd           cmd   = Cmd::UploadLog;
    std::uint8_t  flags = 0;
    std::uint16_t name_len = 0;
    std::uint64_t payload_size = 0;
};

// Serialize header into a fixed byte array (explicit little-endian, portable).
inline std::array<unsigned char, kHeaderSize> encode_header(const FrameHeader& h)
{
    std::array<unsigned char, kHeaderSize> b{};
    auto put32 = [&](std::size_t off, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) b[off + static_cast<std::size_t>(i)] =
            static_cast<unsigned char>((v >> (8 * i)) & 0xFF);
    };
    auto put64 = [&](std::size_t off, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) b[off + static_cast<std::size_t>(i)] =
            static_cast<unsigned char>((v >> (8 * i)) & 0xFF);
    };
    put32(0, h.magic);
    b[4] = static_cast<unsigned char>(h.cmd);
    b[5] = h.flags;
    b[6] = static_cast<unsigned char>(h.name_len & 0xFF);
    b[7] = static_cast<unsigned char>((h.name_len >> 8) & 0xFF);
    put64(8, h.payload_size);
    return b;
}

// Parse and validate a header. Returns false on any malformed field.
inline bool decode_header(const unsigned char* b, std::size_t len, FrameHeader& out)
{
    if (b == nullptr || len < kHeaderSize) return false;
    std::uint32_t magic = 0;
    for (int i = 3; i >= 0; --i) magic = (magic << 8) | b[i];
    if (magic != kMagic) return false;

    const std::uint8_t cmd = b[4];
    if (cmd < static_cast<std::uint8_t>(Cmd::UploadLog) ||
        cmd > static_cast<std::uint8_t>(Cmd::ErrorText)) return false;

    std::uint16_t name_len = static_cast<std::uint16_t>(b[6] | (b[7] << 8));
    if (name_len > kMaxNameLen) return false;

    std::uint64_t sz = 0;
    for (int i = 7; i >= 0; --i) sz = (sz << 8) | b[8 + static_cast<std::size_t>(i)];
    if (sz > kMaxPayloadSize) return false;

    out.magic = magic;
    out.cmd = static_cast<Cmd>(cmd);
    out.flags = b[5];
    out.name_len = name_len;
    out.payload_size = sz;
    return true;
}

// Keep only the base name and drop path separators / control chars so a
// malicious client cannot traverse directories on the server.
inline std::string sanitize_filename(const std::string& raw)
{
    std::string base = raw;
    const std::size_t slash = base.find_last_of("/\\");
    if (slash != std::string::npos) base = base.substr(slash + 1);
    std::string out;
    out.reserve(base.size());
    for (char c : base) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || c == ':' || c == '*' || c == '?' || c == '"' ||
            c == '<' || c == '>' || c == '|') continue;
        out.push_back(c);
    }
    if (out.empty() || out == "." || out == "..") out = "upload.log";
    return out;
}

} // namespace lgx
