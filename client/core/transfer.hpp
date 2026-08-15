// transfer.hpp - cross-platform (Windows/Linux) client transfer engine.
//
// Designed to run on a WORKER THREAD: the GUI thread only reads the atomic
// progress counters, so the UI never freezes during the 500 MB transfer.
//
// STRICT RULE COMPLIANT: no new/delete/malloc; RAII sockets, std containers.
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
  #include <fcntl.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <sys/select.h>
  #include <sys/socket.h>
  #include <unistd.h>
  #include <cerrno>
  using lgx_socket_t = int;
  static constexpr lgx_socket_t kInvalidSock = -1;
#endif

#include "../../common/protocol.hpp"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

namespace lgx {

enum class Stage : int {
    Idle = 0, Connecting, Uploading, WaitingResult, Downloading,
    Done, Failed, Cancelled
};

// Progress shared between the worker thread (writer) and UI thread (reader).
struct Progress {
    std::atomic<int>           stage{static_cast<int>(Stage::Idle)};
    std::atomic<std::uint64_t> sent{0};
    std::atomic<std::uint64_t> send_total{0};
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
        sent = 0; send_total = 0; received = 0; recv_total = 0;
        set_error({});
    }

private:
    mutable std::mutex mutex_;
    std::string error_;
};

namespace detail {

#ifdef _WIN32
// Winsock lifetime bound to an RAII object.
struct WsaGuard {
    bool ok = false;
    WsaGuard()  { WSADATA d{}; ok = (WSAStartup(MAKEWORD(2, 2), &d) == 0); }
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
    ClientSocket(const ClientSocket&) = delete;
    ClientSocket& operator=(const ClientSocket&) = delete;

    lgx_socket_t get() const { return s_; }
    bool valid() const { return s_ != kInvalidSock; }
    void reset()
    {
        if (s_ != kInvalidSock) { close_sock(s_); s_ = kInvalidSock; }
    }
    void adopt(lgx_socket_t s) { reset(); s_ = s; }

private:
    lgx_socket_t s_ = kInvalidSock;
};

inline bool send_all(const ClientSocket& s, const void* data, std::size_t len,
                     const std::atomic<bool>& cancel)
{
    const char* p = static_cast<const char*>(data);
    std::size_t left = len;
    while (left > 0) {
        if (cancel.load(std::memory_order_relaxed)) return false;
#ifdef _WIN32
        const int n = ::send(s.get(), p, static_cast<int>(
            left > 1u << 20 ? 1u << 20 : left), 0);
        if (n == SOCKET_ERROR) return false;
#else
        const ssize_t n = ::send(s.get(), p, left,
#ifdef MSG_NOSIGNAL
                                 MSG_NOSIGNAL
#else
                                 0
#endif
        );
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
#endif
        if (n <= 0) return false;
        p += n;
        left -= static_cast<std::size_t>(n);
    }
    return true;
}

inline bool recv_all(const ClientSocket& s, void* data, std::size_t len,
                     const std::atomic<bool>& cancel)
{
    char* p = static_cast<char*>(data);
    std::size_t left = len;
    while (left > 0) {
        if (cancel.load(std::memory_order_relaxed)) return false;
#ifdef _WIN32
        const int n = ::recv(s.get(), p, static_cast<int>(
            left > 1u << 20 ? 1u << 20 : left), 0);
        if (n == SOCKET_ERROR || n == 0) return false;
#else
        const ssize_t n = ::recv(s.get(), p, left, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
#endif
        p += n;
        left -= static_cast<std::size_t>(n);
    }
    return true;
}

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

// RAII wrapper for getaddrinfo results.
struct AddrInfoHolder {
    addrinfo* res = nullptr;
    ~AddrInfoHolder() { if (res != nullptr) ::freeaddrinfo(res); }
};

inline bool set_nonblocking(lgx_socket_t s, bool nb)
{
#ifdef _WIN32
    u_long mode = nb ? 1u : 0u;
    return ::ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    const int fl = ::fcntl(s, F_GETFL, 0);
    if (fl < 0) return false;
    return ::fcntl(s, F_SETFL, nb ? (fl | O_NONBLOCK)
                                  : (fl & ~O_NONBLOCK)) >= 0;
#endif
}

// Cancellable connect with a hard timeout. Polls in 100 ms slices so the
// worker thread reacts to the Cancel button even while connecting to an
// unreachable host (a plain blocking connect() can hang for ~2 minutes).
inline bool connect_with_timeout(const ClientSocket& sock, const sockaddr* addr,
                                 std::size_t addrlen, int timeout_ms,
                                 const std::atomic<bool>& cancel)
{
    if (!set_nonblocking(sock.get(), true)) return false;

    bool ok = false;
    const int rc = ::connect(sock.get(), addr,
                             static_cast<socklen_t>(addrlen));
    if (rc == 0) {
        ok = true; // connected instantly (e.g. localhost)
    } else {
#ifdef _WIN32
        const bool in_progress = (::WSAGetLastError() == WSAEWOULDBLOCK);
#else
        const bool in_progress = (errno == EINPROGRESS);
#endif
        if (in_progress) {
            for (int waited = 0; waited < timeout_ms; waited += 100) {
                if (cancel.load(std::memory_order_relaxed)) break;
                fd_set wset;
                fd_set eset;
                FD_ZERO(&wset);
                FD_ZERO(&eset);
                FD_SET(sock.get(), &wset);
                FD_SET(sock.get(), &eset);
                timeval tv{};
                tv.tv_usec = 100 * 1000;
                const int n = ::select(static_cast<int>(sock.get()) + 1,
                                       nullptr, &wset, &eset, &tv);
                if (n < 0) break;      // select failed - give up
                if (n == 0) continue;  // still connecting - poll cancel flag
                int err = 0;
#ifdef _WIN32
                int elen = sizeof(err);
                ::getsockopt(sock.get(), SOL_SOCKET, SO_ERROR,
                             reinterpret_cast<char*>(&err), &elen);
#else
                socklen_t elen = sizeof(err);
                ::getsockopt(sock.get(), SOL_SOCKET, SO_ERROR, &err, &elen);
#endif
                ok = (err == 0);
                break; // definitive answer either way
            }
        }
    }
    if (!set_nonblocking(sock.get(), false)) return false;
    return ok;
}

} // namespace detail

// ---------------------------------------------------------------------------
// Upload `log_path`, then receive result.csv into `result_path`.
// Returns true on success; on failure `prog.error()` explains why.
// Never throws out; never crashes on abrupt disconnects.
// ---------------------------------------------------------------------------
inline bool run_transfer(const std::string& host, std::uint16_t port,
                         const std::filesystem::path& log_path,
                         const std::filesystem::path& result_path,
                         Progress& prog, const std::atomic<bool>& cancel)
{
    using namespace detail;
    try {
#ifdef _WIN32
        WsaGuard wsa;
        if (!wsa.ok) { prog.set_error("WSAStartup failed"); prog.set_stage(Stage::Failed); return false; }
#endif
        // ---- open input file ------------------------------------------------
        std::error_code fec;
        const std::uint64_t fsize = std::filesystem::file_size(log_path, fec);
        if (fec) {
            prog.set_error("cannot stat file: " + log_path.string());
            prog.set_stage(Stage::Failed);
            return false;
        }
        std::ifstream in(log_path, std::ios::binary);
        if (!in) {
            prog.set_error("cannot open file: " + log_path.string());
            prog.set_stage(Stage::Failed);
            return false;
        }
        prog.send_total.store(fsize);

        // ---- connect ----------------------------------------------------------
        prog.set_stage(Stage::Connecting);
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        AddrInfoHolder ai;
        const std::string port_str = std::to_string(port);
        if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &ai.res) != 0 ||
            ai.res == nullptr) {
            prog.set_error("cannot resolve host: " + host);
            prog.set_stage(Stage::Failed);
            return false;
        }

        ClientSocket sock;
        for (addrinfo* p = ai.res; p != nullptr; p = p->ai_next) {
            lgx_socket_t s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (s == kInvalidSock) continue;
            sock.adopt(s);
            if (connect_with_timeout(sock, p->ai_addr, p->ai_addrlen,
                                     /*timeout_ms=*/10000, cancel)) break;
            sock.reset();
        }
        if (cancel.load()) {
            prog.set_error("cancelled by user");
            prog.set_stage(Stage::Cancelled);
            return false;
        }
        if (!sock.valid()) {
            prog.set_error("cannot connect to " + host + ":" + port_str +
                           " (refused or 10s timeout)");
            prog.set_stage(Stage::Failed);
            return false;
        }
        set_timeouts(sock, 120);

        // ---- upload -----------------------------------------------------------
        prog.set_stage(Stage::Uploading);
        FrameHeader hdr;
        hdr.cmd = Cmd::UploadLog;
        const std::string fname = log_path.filename().string();
        hdr.name_len = static_cast<std::uint16_t>(
            fname.size() > kMaxNameLen ? kMaxNameLen : fname.size());
        hdr.payload_size = fsize;
        const auto hdr_bytes = encode_header(hdr);
        if (!send_all(sock, hdr_bytes.data(), hdr_bytes.size(), cancel) ||
            !send_all(sock, fname.data(), hdr.name_len, cancel)) {
            prog.set_error(cancel ? "cancelled" : "connection lost while sending header");
            prog.set_stage(cancel ? Stage::Cancelled : Stage::Failed);
            return false;
        }

        std::vector<char> buf(kChunkSize);
        std::uint64_t sent = 0;
        while (sent < fsize) {
            if (cancel.load()) {
                prog.set_error("cancelled by user");
                prog.set_stage(Stage::Cancelled);
                return false;
            }
            const std::uint64_t left = fsize - sent;
            const std::size_t want = static_cast<std::size_t>(
                left > buf.size() ? buf.size() : left);
            in.read(buf.data(), static_cast<std::streamsize>(want));
            const std::streamsize got = in.gcount();
            if (got <= 0) {
                prog.set_error("file shrank while reading");
                prog.set_stage(Stage::Failed);
                return false;
            }
            if (!send_all(sock, buf.data(), static_cast<std::size_t>(got), cancel)) {
                prog.set_error(cancel ? "cancelled by user"
                                      : "connection lost during upload "
                                        "(server down or network dropped)");
                prog.set_stage(cancel ? Stage::Cancelled : Stage::Failed);
                return false;
            }
            sent += static_cast<std::uint64_t>(got);
            prog.sent.store(sent);
        }

        // ---- wait for the analysis result --------------------------------------
        prog.set_stage(Stage::WaitingResult);
        unsigned char rhdr_bytes[kHeaderSize];
        if (!recv_all(sock, rhdr_bytes, sizeof(rhdr_bytes), cancel)) {
            prog.set_error(cancel ? "cancelled by user"
                                  : "connection lost while waiting for result");
            prog.set_stage(cancel ? Stage::Cancelled : Stage::Failed);
            return false;
        }
        FrameHeader rhdr;
        if (!decode_header(rhdr_bytes, sizeof(rhdr_bytes), rhdr)) {
            prog.set_error("malformed response from server");
            prog.set_stage(Stage::Failed);
            return false;
        }
        std::string rname(rhdr.name_len, '\0');
        if (rhdr.name_len > 0 &&
            !recv_all(sock, rname.data(), rname.size(), cancel)) {
            prog.set_error("connection lost reading response name");
            prog.set_stage(Stage::Failed);
            return false;
        }

        if (rhdr.cmd == Cmd::ErrorText) {
            std::string msg(static_cast<std::size_t>(
                rhdr.payload_size > 4096 ? 4096 : rhdr.payload_size), '\0');
            recv_all(sock, msg.data(), msg.size(), cancel);
            prog.set_error("server error: " + msg);
            prog.set_stage(Stage::Failed);
            return false;
        }
        if (rhdr.cmd != Cmd::ResultCsv) {
            prog.set_error("unexpected response command");
            prog.set_stage(Stage::Failed);
            return false;
        }

        // ---- download result.csv ------------------------------------------------
        prog.set_stage(Stage::Downloading);
        prog.recv_total.store(rhdr.payload_size);
        std::ofstream out(result_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            prog.set_error("cannot write " + result_path.string());
            prog.set_stage(Stage::Failed);
            return false;
        }
        std::uint64_t recvd = 0;
        while (recvd < rhdr.payload_size) {
            if (cancel.load()) {
                prog.set_error("cancelled by user");
                prog.set_stage(Stage::Cancelled);
                return false;
            }
            const std::uint64_t left = rhdr.payload_size - recvd;
            const std::size_t want = static_cast<std::size_t>(
                left > buf.size() ? buf.size() : left);
            if (!recv_all(sock, buf.data(), want, cancel)) {
                prog.set_error("connection lost during result download");
                prog.set_stage(Stage::Failed);
                return false;
            }
            out.write(buf.data(), static_cast<std::streamsize>(want));
            recvd += want;
            prog.received.store(recvd);
        }
        out.flush();
        if (!out) {
            prog.set_error("disk write failed for " + result_path.string());
            prog.set_stage(Stage::Failed);
            return false;
        }

        prog.set_stage(Stage::Done);
        return true;
    } catch (const std::exception& ex) {
        prog.set_error(std::string("exception: ") + ex.what());
        prog.set_stage(Stage::Failed);
        return false;
    } catch (...) {
        prog.set_error("unknown exception");
        prog.set_stage(Stage::Failed);
        return false;
    }
}

} // namespace lgx
