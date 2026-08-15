// SHA-256 helper backed by the vendored Mbed TLS implementation.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include <mbedtls/sha256.h>

namespace lgx {

constexpr std::size_t kSha256Size = 32;
using Sha256Digest = std::array<unsigned char, kSha256Size>;

class Sha256 {
public:
    Sha256()
    {
        mbedtls_sha256_init(&ctx_);
        ok_ = (mbedtls_sha256_starts(&ctx_, 0) == 0);
    }
    ~Sha256() { mbedtls_sha256_free(&ctx_); }

    bool update(const void* data, std::size_t len)
    {
        if (!ok_) return false;
        ok_ = (mbedtls_sha256_update(
            &ctx_, static_cast<const unsigned char*>(data), len) == 0);
        return ok_;
    }

    bool finish(Sha256Digest& out)
    {
        if (!ok_ || finished_) return false;
        ok_ = (mbedtls_sha256_finish(&ctx_, out.data()) == 0);
        finished_ = true;
        return ok_;
    }

private:
    Sha256(const Sha256&);
    Sha256& operator=(const Sha256&);
    mbedtls_sha256_context ctx_{};
    bool ok_ = false;
    bool finished_ = false;
};

inline std::string hex_encode(const unsigned char* data, std::size_t len)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out[i * 2] = kHex[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHex[data[i] & 0x0F];
    }
    return out;
}

inline bool hex_decode(const std::string& text, unsigned char* out,
                       std::size_t out_len)
{
    if (text.size() != out_len * 2) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < out_len; ++i) {
        const int hi = nibble(text[i * 2]);
        const int lo = nibble(text[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return true;
}

inline bool digest_equal(const Sha256Digest& a, const Sha256Digest& b)
{
    unsigned int diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned int>(a[i] ^ b[i]);
    return diff == 0;
}

} // namespace lgx
