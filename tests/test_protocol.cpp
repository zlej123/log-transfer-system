// Self-contained LGX2 framing and SHA-256 tests.
#include "../common/protocol.hpp"

#include <array>
#include <cstdio>
#include <string>

static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::printf("FAIL line %d: %s\n", __LINE__, #x); ++failures; } } while (0)

void check_sha(const std::string& input, const std::string& expected)
{
    lgx::Sha256 hash;
    lgx::Sha256Digest digest{};
    CHECK(hash.update(input.data(), input.size()));
    CHECK(hash.finish(digest));
    CHECK(lgx::hex_encode(digest.data(), digest.size()) == expected);
}

int main()
{
    check_sha("", "e3b0c44298fc1c149afbf4c8996fb924"
                  "27ae41e4649b934ca495991b7852b855");
    check_sha("abc", "ba7816bf8f01cfea414140de5dae2223"
                     "b00361a396177a9cb410ff61f20015ad");
    check_sha(std::string(1000000, 'a'),
              "cdc76e5c9914fb9281a1c7e284d73e67"
              "f1809a48a497200e046d39ccc7112cd0");

    lgx::FrameHeader h;
    h.cmd = lgx::Cmd::UploadInit;
    h.name_len = 0x0234;
    h.payload_size = 0x0000000105060708ull;
    const auto encoded = lgx::encode_header(h);
    const std::array<unsigned char, lgx::kHeaderSize> golden = {
        0x4c,0x47,0x58,0x32, 0x01,0x00,0x02,0x34,
        0x00,0x00,0x00,0x01,0x05,0x06,0x07,0x08};
    CHECK(encoded == golden);
    lgx::FrameHeader decoded;
    CHECK(lgx::decode_header(encoded.data(), encoded.size(), decoded));
    CHECK(decoded.name_len == 0x0234);
    CHECK(decoded.payload_size == h.payload_size);

    for (std::size_t length = 0; length < lgx::kHeaderSize; ++length)
        CHECK(!lgx::decode_header(encoded.data(), length, decoded));

    auto invalid = encoded;
    invalid[0] ^= 1;
    CHECK(!lgx::decode_header(invalid.data(), invalid.size(), decoded));
    invalid = encoded;
    invalid[5] = 1; // reserved flags on a non-error frame
    CHECK(!lgx::decode_header(invalid.data(), invalid.size(), decoded));
    invalid = encoded;
    invalid[4] = 99;
    CHECK(!lgx::decode_header(invalid.data(), invalid.size(), decoded));

    lgx::FrameHeader error;
    error.cmd = lgx::Cmd::ErrorText;
    error.flags = static_cast<std::uint8_t>(lgx::ErrorCode::Storage);
    auto error_bytes = lgx::encode_header(error);
    CHECK(lgx::decode_header(error_bytes.data(), error_bytes.size(), decoded));
    error_bytes[5] = 255;
    CHECK(!lgx::decode_header(error_bytes.data(), error_bytes.size(), decoded));
    error_bytes[5] = 0;
    CHECK(!lgx::decode_header(error_bytes.data(), error_bytes.size(), decoded));

    CHECK(lgx::sanitize_filename("../../bad\\path:<x>.log") == "pathx.log");
    CHECK(lgx::sanitize_filename("..") == "upload.log");

    if (failures == 0) {
        std::printf("ALL PROTOCOL TESTS PASSED\n");
        return 0;
    }
    return 1;
}
