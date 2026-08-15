// Cross-platform worker-thread transfer engine: TLS, resume and SHA-256.
#pragma once

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  using lgx_socket_t = SOCKET;
  static constexpr lgx_socket_t kInvalidSock = INVALID_SOCKET;
#else
  #include <arpa/inet.h>
  #include <cerrno>
  #include <fcntl.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <sys/select.h>
  #include <sys/socket.h>
  #include <sys/stat.h>
  #include <unistd.h>
  using lgx_socket_t = int;
  static constexpr lgx_socket_t kInvalidSock = -1;
#endif

#include "../../common/protocol.hpp"
#include "../../common/tls.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace lgx {

enum class Stage : int {
    Idle = 0, Hashing, Connecting, TlsHandshake, Negotiating, Uploading,
    WaitingResult, Downloading, Done, Failed, Cancelled
};

struct Progress {
    std::atomic<int> stage{static_cast<int>(Stage::Idle)};
    std::atomic<std::uint64_t> hashed{0};
    std::atomic<std::uint64_t> hash_total{0};
    std::atomic<std::uint64_t> sent{0};
    std::atomic<std::uint64_t> send_total{0};
    std::atomic<std::uint64_t> resumed_offset{0};
    std::atomic<std::uint64_t> received{0};
    std::atomic<std::uint64_t> recv_total{0};

    void set_stage(Stage s) { stage.store(static_cast<int>(s)); }
    Stage get_stage() const { return static_cast<Stage>(stage.load()); }

    void set_error(const std::string& msg)
    {
        std::lock_guard<std::mutex> lk(mutex_);
        error_ = msg;
    }
    std::string error() const
    {
        std::lock_guard<std::mutex> lk(mutex_);
        return error_;
    }
    void reset()
    {
        set_stage(Stage::Idle);
        hashed = 0; hash_total = 0;
        sent = 0; send_total = 0; resumed_offset = 0;
        received = 0; recv_total = 0;
        set_error({});
    }

private:
    mutable std::mutex mutex_;
    std::string error_;
};

namespace detail {

#ifdef _WIN32
struct WsaGuard {
    bool ok = false;
    WsaGuard() { WSADATA d{}; ok = (WSAStartup(MAKEWORD(2, 2), &d) == 0); }
    ~WsaGuard() { if (ok) WSACleanup(); }
};
inline void close_sock(lgx_socket_t s) { ::closesocket(s); }
#else
inline void close_sock(lgx_socket_t s) { ::close(s); }
#endif

class ClientSocket {
public:
    ClientSocket() = default;
    explicit ClientSocket(lgx_socket_t s) : s_(s) {}
    ~ClientSocket() { reset(); }

    lgx_socket_t get() const { return s_; }
    bool valid() const { return s_ != kInvalidSock; }
    void reset()
    {
        if (s_ != kInvalidSock) { close_sock(s_); s_ = kInvalidSock; }
    }
    void adopt(lgx_socket_t s) { reset(); s_ = s; }

private:
    ClientSocket(const ClientSocket&);
    ClientSocket& operator=(const ClientSocket&);
    lgx_socket_t s_ = kInvalidSock;
};

class SecureOutput {
public:
    explicit SecureOutput(const std::filesystem::path& path)
    {
#ifdef _WIN32
        handle_ = ::CreateFileW(path.wstring().c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
#else
        fd_ = ::open(path.c_str(),
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                     0600);
#endif
    }
    ~SecureOutput()
    {
#ifdef _WIN32
        if (handle_ != INVALID_HANDLE_VALUE) ::CloseHandle(handle_);
#else
        if (fd_ >= 0) ::close(fd_);
#endif
    }

    bool valid() const
    {
#ifdef _WIN32
        return handle_ != INVALID_HANDLE_VALUE;
#else
        return fd_ >= 0;
#endif
    }

    bool write_all(const void* data, std::size_t size)
    {
        const char* current = static_cast<const char*>(data);
        std::size_t remaining = size;
        while (remaining > 0) {
#ifdef _WIN32
            DWORD count = 0;
            const DWORD request = static_cast<DWORD>(
                std::min<std::size_t>(remaining, 1u << 20));
            if (::WriteFile(handle_, current, request, &count, nullptr) == 0 ||
                count == 0) return false;
#else
            const ssize_t count = ::write(fd_, current, remaining);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) return false;
#endif
            current += count;
            remaining -= static_cast<std::size_t>(count);
        }
        return true;
    }

    bool sync_close()
    {
#ifdef _WIN32
        if (handle_ == INVALID_HANDLE_VALUE || ::FlushFileBuffers(handle_) == 0)
            return false;
        ::CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
#else
        if (fd_ < 0 || ::fsync(fd_) != 0) return false;
        ::close(fd_);
        fd_ = -1;
#endif
        return true;
    }

private:
    SecureOutput(const SecureOutput&);
    SecureOutput& operator=(const SecureOutput&);
#ifdef _WIN32
    HANDLE handle_ = INVALID_HANDLE_VALUE;
#else
    int fd_ = -1;
#endif
};

inline void set_timeouts(const ClientSocket& s, int seconds)
{
#ifdef _WIN32
    const DWORD ms = static_cast<DWORD>(seconds) * 1000u;
    ::setsockopt(s.get(), SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&ms), sizeof(ms));
    ::setsockopt(s.get(), SOL_SOCKET, SO_SNDTIMEO,
                 reinterpret_cast<const char*>(&ms), sizeof(ms));
#else
    timeval tv{};
    tv.tv_sec = seconds;
    ::setsockopt(s.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(s.get(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

struct AddrInfoHolder {
    addrinfo* res = nullptr;
    ~AddrInfoHolder() { if (res != nullptr) ::freeaddrinfo(res); }
};

inline bool set_nonblocking(lgx_socket_t s, bool enabled)
{
#ifdef _WIN32
    u_long mode = enabled ? 1u : 0u;
    return ::ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    const int flags = ::fcntl(s, F_GETFL, 0);
    if (flags < 0) return false;
    return ::fcntl(s, F_SETFL, enabled ? (flags | O_NONBLOCK)
                                      : (flags & ~O_NONBLOCK)) >= 0;
#endif
}

inline bool connect_with_timeout(const ClientSocket& sock, const sockaddr* addr,
                                 std::size_t addrlen, int timeout_ms,
                                 const std::atomic<bool>& cancel)
{
    if (!set_nonblocking(sock.get(), true)) return false;
    bool ok = false;
    const int rc = ::connect(sock.get(), addr,
                             static_cast<socklen_t>(addrlen));
    if (rc == 0) {
        ok = true;
    } else {
#ifdef _WIN32
        const bool pending = (::WSAGetLastError() == WSAEWOULDBLOCK);
#else
        const bool pending = (errno == EINPROGRESS);
#endif
        if (pending) {
            for (int waited = 0; waited < timeout_ms; waited += 100) {
                if (cancel.load(std::memory_order_relaxed)) break;
                fd_set writes;
                fd_set errors;
                FD_ZERO(&writes); FD_ZERO(&errors);
                FD_SET(sock.get(), &writes); FD_SET(sock.get(), &errors);
                timeval tv{};
                tv.tv_usec = 100 * 1000;
                const int n = ::select(static_cast<int>(sock.get()) + 1,
                                       nullptr, &writes, &errors, &tv);
                if (n < 0) break;
                if (n == 0) continue;
                int socket_error = 0;
#ifdef _WIN32
                int error_len = sizeof(socket_error);
                ::getsockopt(sock.get(), SOL_SOCKET, SO_ERROR,
                             reinterpret_cast<char*>(&socket_error), &error_len);
#else
                socklen_t error_len = sizeof(socket_error);
                ::getsockopt(sock.get(), SOL_SOCKET, SO_ERROR,
                             &socket_error, &error_len);
#endif
                ok = (socket_error == 0);
                break;
            }
        }
    }
    if (!set_nonblocking(sock.get(), false)) return false;
    return ok;
}

inline bool hash_file(std::ifstream& input, std::uint64_t size,
                      Sha256Digest& digest, Progress& progress,
                      const std::atomic<bool>& cancel)
{
    Sha256 hash;
    std::vector<char> chunk(kChunkSize);
    std::uint64_t done = 0;
    while (done < size) {
        if (cancel.load(std::memory_order_relaxed)) return false;
        const std::size_t want = static_cast<std::size_t>(
            std::min<std::uint64_t>(size - done, chunk.size()));
        input.read(chunk.data(), static_cast<std::streamsize>(want));
        const std::streamsize got = input.gcount();
        if (got <= 0 || !hash.update(chunk.data(), static_cast<std::size_t>(got)))
            return false;
        done += static_cast<std::uint64_t>(got);
        progress.hashed.store(done);
    }
    if (!hash.finish(digest)) return false;
    input.clear();
    input.seekg(0, std::ios::beg);
    return static_cast<bool>(input);
}

using ResumeToken = std::array<unsigned char, kResumeTokenSize>;

inline bool authority_digest(const std::filesystem::path& ca_file,
                             const std::string& server_name,
                             std::uint16_t port, Sha256Digest& out)
{
    std::ifstream ca(ca_file, std::ios::binary);
    if (!ca) return false;
    Sha256 hash;
    const std::uint16_t name_len = static_cast<std::uint16_t>(
        std::min<std::size_t>(server_name.size(), 65535));
    const unsigned char prefix[4] = {
        static_cast<unsigned char>((name_len >> 8) & 0xFF),
        static_cast<unsigned char>(name_len & 0xFF),
        static_cast<unsigned char>((port >> 8) & 0xFF),
        static_cast<unsigned char>(port & 0xFF)};
    if (!hash.update(prefix, sizeof(prefix)) ||
        !hash.update(server_name.data(), name_len)) return false;
    std::array<char, 4096> bytes{};
    while (ca) {
        ca.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        const std::streamsize count = ca.gcount();
        if (count > 0 &&
            !hash.update(bytes.data(), static_cast<std::size_t>(count)))
            return false;
    }
    return ca.eof() && hash.finish(out);
}

inline std::filesystem::path resume_sidecar(const std::filesystem::path& result)
{
    return std::filesystem::path(result.string() + ".lgxresume");
}

inline std::string staging_id(const ResumeToken& token)
{
    Sha256 hash;
    Sha256Digest digest{};
    hash.update(token.data(), token.size());
    hash.finish(digest);
    return hex_encode(digest.data(), digest.size());
}

inline ResumeToken load_resume_token(const std::filesystem::path& path,
                                     const Sha256Digest& digest,
                                     const Sha256Digest& authority)
{
    ResumeToken token{};
    std::ifstream in(path, std::ios::binary);
    if (!in) return token;
    std::array<char, 8> magic{};
    Sha256Digest stored_digest{};
    ResumeToken stored_token{};
    Sha256Digest stored_authority{};
    in.read(magic.data(), static_cast<std::streamsize>(magic.size()));
    in.read(reinterpret_cast<char*>(stored_digest.data()),
            static_cast<std::streamsize>(stored_digest.size()));
    in.read(reinterpret_cast<char*>(stored_token.data()),
            static_cast<std::streamsize>(stored_token.size()));
    in.read(reinterpret_cast<char*>(stored_authority.data()),
            static_cast<std::streamsize>(stored_authority.size()));
    static constexpr std::array<char, 8> kSidecarMagic =
        {'L','G','X','R','S','M','3','\0'};
    if (in && magic == kSidecarMagic && digest_equal(stored_digest, digest) &&
        digest_equal(stored_authority, authority))
        token = stored_token;
    return token;
}

inline bool atomic_publish(const std::filesystem::path& part,
                           const std::filesystem::path& destination,
                           std::string& error);

inline bool save_resume_token(const std::filesystem::path& path,
                              const Sha256Digest& digest,
                              const ResumeToken& token,
                              const Sha256Digest& authority)
{
    static constexpr std::array<char, 8> kSidecarMagic =
        {'L','G','X','R','S','M','3','\0'};
    std::string content;
    content.reserve(kSidecarMagic.size() + digest.size() + token.size() +
                    authority.size());
    content.append(kSidecarMagic.data(), kSidecarMagic.size());
    content.append(reinterpret_cast<const char*>(digest.data()), digest.size());
    content.append(reinterpret_cast<const char*>(token.data()), token.size());
    content.append(reinterpret_cast<const char*>(authority.data()), authority.size());

    const auto staging = std::filesystem::path(
        path.string() + "." + staging_id(token) + ".tmp");
    std::error_code cleanup_error;
    std::filesystem::remove(staging, cleanup_error);
    SecureOutput output(staging);
    if (!output.valid() || !output.write_all(content.data(), content.size()) ||
        !output.sync_close())
        return false;
    std::string publish_error;
    return atomic_publish(staging, path, publish_error);
}

inline bool atomic_publish(const std::filesystem::path& part,
                           const std::filesystem::path& destination,
                           std::string& error)
{
#ifdef _WIN32
    if (::MoveFileExW(part.wstring().c_str(), destination.wstring().c_str(),
                      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
        error = "atomic result publish failed";
        return false;
    }
    return true;
#else
    std::error_code ec;
    std::filesystem::rename(part, destination, ec);
    if (ec) { error = "atomic result publish failed: " + ec.message(); return false; }
    const std::filesystem::path parent = destination.has_parent_path()
        ? destination.parent_path() : std::filesystem::path(".");
    const int directory = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) { error = "result directory sync open failed"; return false; }
    const bool synced = (::fsync(directory) == 0);
    ::close(directory);
    if (!synced) { error = "result directory sync failed"; return false; }
    return true;
#endif
}

inline bool read_error_payload(TlsSession& tls, const FrameHeader& header,
                               Progress& progress,
                               const std::atomic<bool>& cancel,
                               const std::filesystem::path& sidecar)
{
    if (header.name_len != 0 || header.payload_size > kMaxErrorSize) {
        progress.set_error("malformed server error frame");
        progress.set_stage(Stage::Failed);
        return false;
    }
    const std::size_t keep = static_cast<std::size_t>(header.payload_size);
    std::string message(keep, '\0');
    if (keep > 0 && !tls.recv_all(message.data(), keep, &cancel))
        message = "server closed while sending an error";
    const auto code = static_cast<ErrorCode>(header.flags);
    if (code == ErrorCode::ResumeInvalid ||
        code == ErrorCode::ChecksumMismatch) {
        std::error_code cleanup_error;
        std::filesystem::remove(sidecar, cleanup_error);
    }
    progress.set_error("server error: " + message);
    progress.set_stage(Stage::Failed);
    return false;
}

} // namespace detail

inline bool run_transfer(const std::string& host, std::uint16_t port,
                         const std::filesystem::path& log_path,
                         const std::filesystem::path& result_path,
                         Progress& progress, const std::atomic<bool>& cancel,
                         const std::filesystem::path& ca_file = "certs/ca.crt",
                         const std::string& expected_server_name = "localhost",
                         const std::filesystem::path& client_cert = "certs/client.crt",
                         const std::filesystem::path& client_key = "certs/client.key")
{
    using namespace detail;
    try {
        if (expected_server_name.empty()) {
            progress.set_error("TLS server name must not be empty");
            progress.set_stage(Stage::Failed);
            return false;
        }
#ifdef _WIN32
        WsaGuard wsa;
        if (!wsa.ok) {
            progress.set_error("WSAStartup failed");
            progress.set_stage(Stage::Failed);
            return false;
        }
#endif
        std::error_code file_error;
        const std::uint64_t file_size =
            std::filesystem::file_size(log_path, file_error);
        if (file_error || file_size > kMaxPayloadSize) {
            progress.set_error("cannot stat file or file exceeds protocol limit: " +
                               log_path.string());
            progress.set_stage(Stage::Failed);
            return false;
        }
        std::ifstream input(log_path, std::ios::binary);
        if (!input) {
            progress.set_error("cannot open file: " + log_path.string());
            progress.set_stage(Stage::Failed);
            return false;
        }

        progress.hash_total.store(file_size);
        progress.send_total.store(file_size);
        progress.set_stage(Stage::Hashing);
        Sha256Digest digest{};
        if (!hash_file(input, file_size, digest, progress, cancel)) {
            progress.set_error(cancel.load() ? "cancelled while hashing"
                                             : "file changed or hashing failed");
            progress.set_stage(cancel.load() ? Stage::Cancelled : Stage::Failed);
            return false;
        }

        progress.set_stage(Stage::Connecting);
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        AddrInfoHolder addresses;
        const std::string port_text = std::to_string(port);
        if (::getaddrinfo(host.c_str(), port_text.c_str(), &hints,
                          &addresses.res) != 0 || addresses.res == nullptr) {
            progress.set_error("cannot resolve host: " + host);
            progress.set_stage(Stage::Failed);
            return false;
        }

        ClientSocket socket;
        for (addrinfo* p = addresses.res; p != nullptr; p = p->ai_next) {
            const lgx_socket_t candidate =
                ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (candidate == kInvalidSock) continue;
            socket.adopt(candidate);
            if (connect_with_timeout(socket, p->ai_addr, p->ai_addrlen,
                                     10000, cancel)) break;
            socket.reset();
        }
        if (cancel.load()) {
            progress.set_error("cancelled by user");
            progress.set_stage(Stage::Cancelled);
            return false;
        }
        if (!socket.valid()) {
            progress.set_error("cannot connect to " + host + ":" + port_text +
                               " (refused or 10s timeout)");
            progress.set_stage(Stage::Failed);
            return false;
        }

        set_timeouts(socket, 1);
        progress.set_stage(Stage::TlsHandshake);
        TlsClientConfig tls_config;
        std::string tls_error;
        if (!tls_config.setup(ca_file.string(), client_cert.string(),
                              client_key.string(), tls_error)) {
            progress.set_error(tls_error);
            progress.set_stage(Stage::Failed);
            return false;
        }
        TlsSession tls;
        if (!tls.setup(tls_config.raw(), socket.get(), expected_server_name,
                       tls_error) ||
            !tls.handshake(&cancel, tls_error) ||
            tls.verify_result() != 0 || !tls.alpn_is_lgx2()) {
            progress.set_error(tls_error.empty()
                ? "TLS certificate verification failed" : tls_error);
            progress.set_stage(cancel.load() ? Stage::Cancelled : Stage::Failed);
            return false;
        }
        set_timeouts(socket, 1);

        progress.set_stage(Stage::Negotiating);
        Sha256Digest authority{};
        if (!authority_digest(ca_file, expected_server_name, port, authority)) {
            progress.set_error("cannot hash TLS authority configuration");
            progress.set_stage(Stage::Failed);
            return false;
        }
        const std::filesystem::path sidecar = resume_sidecar(result_path);
        ResumeToken token = load_resume_token(sidecar, digest, authority);
        const std::string file_name = log_path.filename().string();
        FrameHeader init;
        init.cmd = Cmd::UploadInit;
        init.name_len = static_cast<std::uint16_t>(
            std::min<std::size_t>(file_name.size(), kMaxNameLen));
        init.payload_size = file_size;
        const auto init_bytes = encode_header(init);
        if (!tls.send_all(init_bytes.data(), init_bytes.size(), &cancel) ||
            !tls.send_all(file_name.data(), init.name_len, &cancel) ||
            !tls.send_all(digest.data(), digest.size(), &cancel) ||
            !tls.send_all(token.data(), token.size(), &cancel)) {
            progress.set_error("TLS connection lost during upload negotiation");
            progress.set_stage(cancel.load() ? Stage::Cancelled : Stage::Failed);
            return false;
        }

        unsigned char response_bytes[kHeaderSize]{};
        if (!tls.recv_all(response_bytes, sizeof(response_bytes), &cancel)) {
            progress.set_error("TLS connection lost waiting for resume state");
            progress.set_stage(cancel.load() ? Stage::Cancelled : Stage::Failed);
            return false;
        }
        FrameHeader response;
        if (!decode_header(response_bytes, sizeof(response_bytes), response)) {
            progress.set_error("malformed resume response");
            progress.set_stage(Stage::Failed);
            return false;
        }
        if (response.cmd == Cmd::ErrorText)
            return read_error_payload(tls, response, progress, cancel, sidecar);
        if (response.cmd != Cmd::ResumeInfo || response.name_len != 0 ||
            response.payload_size > file_size ||
            !tls.recv_all(token.data(), token.size(), &cancel)) {
            progress.set_error("invalid resume offset or token");
            progress.set_stage(Stage::Failed);
            return false;
        }
        if (!save_resume_token(sidecar, digest, token, authority)) {
            progress.set_error("cannot persist resume token: " + sidecar.string());
            progress.set_stage(Stage::Failed);
            return false;
        }

        const std::uint64_t offset = response.payload_size;
        progress.resumed_offset.store(offset);
        progress.sent.store(offset);
        input.clear();
        input.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        if (!input) {
            progress.set_error("cannot seek input to resume offset");
            progress.set_stage(Stage::Failed);
            return false;
        }

        progress.set_stage(Stage::Uploading);
        std::vector<char> chunk(kChunkSize);
        std::uint64_t sent = offset;
        while (sent < file_size) {
            if (cancel.load()) {
                progress.set_error("cancelled by user; resume state retained");
                progress.set_stage(Stage::Cancelled);
                return false;
            }
            const std::size_t want = static_cast<std::size_t>(
                std::min<std::uint64_t>(file_size - sent, chunk.size()));
            input.read(chunk.data(), static_cast<std::streamsize>(want));
            const std::streamsize got = input.gcount();
            if (got <= 0) {
                progress.set_error("file changed while uploading");
                progress.set_stage(Stage::Failed);
                return false;
            }
            if (!tls.send_all(chunk.data(), static_cast<std::size_t>(got),
                              &cancel)) {
                progress.set_error("TLS connection lost; retry will resume");
                progress.set_stage(cancel.load() ? Stage::Cancelled : Stage::Failed);
                return false;
            }
            sent += static_cast<std::uint64_t>(got);
            progress.sent.store(sent);
        }

        progress.set_stage(Stage::WaitingResult);
        unsigned char result_header_bytes[kHeaderSize]{};
        if (!tls.recv_all(result_header_bytes, sizeof(result_header_bytes),
                          &cancel)) {
            progress.set_error("connection lost waiting for verified result; retry will resume");
            progress.set_stage(cancel.load() ? Stage::Cancelled : Stage::Failed);
            return false;
        }
        FrameHeader result_header;
        if (!decode_header(result_header_bytes, sizeof(result_header_bytes),
                           result_header)) {
            progress.set_error("malformed result response");
            progress.set_stage(Stage::Failed);
            return false;
        }
        if (result_header.cmd == Cmd::ErrorText)
            return read_error_payload(tls, result_header, progress, cancel, sidecar);
        if (result_header.cmd != Cmd::ResultCsv ||
            result_header.payload_size > kMaxResultSize) {
            progress.set_error("unexpected or oversized result response");
            progress.set_stage(Stage::Failed);
            return false;
        }
        std::string result_name(result_header.name_len, '\0');
        if (result_header.name_len > 0 &&
            !tls.recv_all(result_name.data(), result_name.size(), &cancel)) {
            progress.set_error("connection lost reading result name");
            progress.set_stage(Stage::Failed);
            return false;
        }
        Sha256Digest expected_result_digest{};
        if (!tls.recv_all(expected_result_digest.data(),
                          expected_result_digest.size(), &cancel)) {
            progress.set_error("connection lost reading result checksum");
            progress.set_stage(Stage::Failed);
            return false;
        }

        progress.set_stage(Stage::Downloading);
        progress.recv_total.store(result_header.payload_size);
        const std::filesystem::path result_part = std::filesystem::path(
            result_path.string() + "." + staging_id(token) + ".part");
        std::error_code stale_part_error;
        std::filesystem::remove(result_part, stale_part_error);
        SecureOutput output(result_part);
        if (!output.valid()) {
            progress.set_error("cannot write result staging file");
            progress.set_stage(Stage::Failed);
            return false;
        }
        Sha256 result_hash;
        std::uint64_t received = 0;
        while (received < result_header.payload_size) {
            const std::size_t want = static_cast<std::size_t>(
                std::min<std::uint64_t>(result_header.payload_size - received,
                                        chunk.size()));
            if (!tls.recv_all(chunk.data(), want, &cancel)) {
                progress.set_error("TLS connection lost during result download; retry will resume");
                progress.set_stage(cancel.load() ? Stage::Cancelled : Stage::Failed);
                return false;
            }
            if (!result_hash.update(chunk.data(), want)) {
                progress.set_error("result SHA-256 update failed");
                progress.set_stage(Stage::Failed);
                return false;
            }
            if (!output.write_all(chunk.data(), want)) {
                progress.set_error("result staging write failed");
                progress.set_stage(Stage::Failed);
                return false;
            }
            received += want;
            progress.received.store(received);
        }
        if (!output.sync_close()) {
            progress.set_error("result staging sync failed");
            progress.set_stage(Stage::Failed);
            return false;
        }
        Sha256Digest actual_result_digest{};
        if (!result_hash.finish(actual_result_digest) ||
            !digest_equal(expected_result_digest, actual_result_digest)) {
            std::error_code cleanup_error;
            std::filesystem::remove(result_part, cleanup_error);
            progress.set_error("result SHA-256 mismatch; prior result preserved");
            progress.set_stage(Stage::Failed);
            return false;
        }
        std::string publish_error;
        if (!atomic_publish(result_part, result_path, publish_error)) {
            progress.set_error(publish_error);
            progress.set_stage(Stage::Failed);
            return false;
        }

        std::error_code remove_error;
        std::filesystem::remove(sidecar, remove_error);
        tls.close_notify();
        progress.set_stage(Stage::Done);
        return true;
    } catch (const std::exception& ex) {
        progress.set_error(std::string("exception: ") + ex.what());
        progress.set_stage(Stage::Failed);
        return false;
    } catch (...) {
        progress.set_error("unknown exception");
        progress.set_stage(Stage::Failed);
        return false;
    }
}

} // namespace lgx
