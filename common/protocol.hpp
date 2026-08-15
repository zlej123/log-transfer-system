// protocol.hpp - shared LGX2 wire framing (network byte order)
// STRICT RULE COMPLIANT: header-only RAII and STL storage.
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <array>

#include "hash.hpp"

namespace lgx {

// ---------------------------------------------------------------------------
// TLS-protected wire protocol v2
//
//   Upload initialization (client -> server):
//     [header: cmd=UPLOAD_INIT, payload_size=complete file size]
//     [UTF-8 file name][32-byte SHA-256][32-byte resume token]
//
//   Resume response (server -> client):
//     [header: cmd=RESUME_INFO, payload_size=accepted byte offset]
//     [32-byte opaque resume token]
//
//   The client streams bytes [offset, file_size). The server persists a
//   bounded-memory partial file, verifies SHA-256, analyzes it in chunks, and
//   replies with RESULT_CSV followed by name, result SHA-256 and CSV bytes.
//   ERROR_TEXT carries a bounded UTF-8 payload and a stable error code.
// ---------------------------------------------------------------------------

constexpr std::uint32_t kMagic = 0x4C475832u; // ASCII "LGX2"
constexpr std::uint16_t kDefaultPort = 45777;

enum class Cmd : std::uint8_t {
    UploadInit  = 1,
    ResumeInfo = 2,
    ResultCsv  = 3,
    ErrorText  = 4,
};

enum class ErrorCode : std::uint8_t {
    None = 0,
    Protocol = 1,
    ResumeInvalid = 2,
    ChecksumMismatch = 3,
    ServerBusy = 4,
    Storage = 5,
    Internal = 6,
};

constexpr std::size_t   kHeaderSize     = 16;                    // fixed part
constexpr std::size_t   kResumeTokenSize = 32;
constexpr std::size_t   kUploadMetaSize  = kSha256Size + kResumeTokenSize;
constexpr std::uint16_t kMaxNameLen     = 1024;                  // sanity cap
constexpr std::uint64_t kMaxPayloadSize = 8ull * 1024 * 1024 * 1024; // 8 GiB cap
constexpr std::uint64_t kMaxResultSize  = 64ull * 1024 * 1024;
constexpr std::uint64_t kMaxErrorSize   = 1024;
constexpr std::size_t   kChunkSize      = 64 * 1024;             // stream chunk

struct FrameHeader {
    std::uint32_t magic = kMagic;
    Cmd           cmd   = Cmd::UploadInit;
    std::uint8_t  flags = 0;
    std::uint16_t name_len = 0;
    std::uint64_t payload_size = 0;
};

// Serialize a fixed network-byte-order header.
inline std::array<unsigned char, kHeaderSize> encode_header(const FrameHeader& h)
{
    std::array<unsigned char, kHeaderSize> b{};
    auto put32 = [&](std::size_t off, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) b[off + static_cast<std::size_t>(i)] =
            static_cast<unsigned char>((v >> (8 * (3 - i))) & 0xFF);
    };
    auto put64 = [&](std::size_t off, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) b[off + static_cast<std::size_t>(i)] =
            static_cast<unsigned char>((v >> (8 * (7 - i))) & 0xFF);
    };
    put32(0, h.magic);
    b[4] = static_cast<unsigned char>(h.cmd);
    b[5] = h.flags;
    b[6] = static_cast<unsigned char>((h.name_len >> 8) & 0xFF);
    b[7] = static_cast<unsigned char>(h.name_len & 0xFF);
    put64(8, h.payload_size);
    return b;
}

// Parse and validate a header. Returns false on any malformed field.
inline bool decode_header(const unsigned char* b, std::size_t len, FrameHeader& out)
{
    if (b == nullptr || len < kHeaderSize) return false;
    std::uint32_t magic = 0;
    for (int i = 0; i < 4; ++i) magic = (magic << 8) | b[i];
    if (magic != kMagic) return false;

    const std::uint8_t cmd = b[4];
    if (cmd < static_cast<std::uint8_t>(Cmd::UploadInit) ||
        cmd > static_cast<std::uint8_t>(Cmd::ErrorText)) return false;
    if (cmd == static_cast<std::uint8_t>(Cmd::ErrorText)) {
        if (b[5] == 0 ||
            b[5] > static_cast<std::uint8_t>(ErrorCode::Internal)) return false;
    } else if (b[5] != 0) {
        return false;
    }

    std::uint16_t name_len = static_cast<std::uint16_t>((b[6] << 8) | b[7]);
    if (name_len > kMaxNameLen) return false;

    std::uint64_t sz = 0;
    for (int i = 0; i < 8; ++i)
        sz = (sz << 8) | b[8 + static_cast<std::size_t>(i)];
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
