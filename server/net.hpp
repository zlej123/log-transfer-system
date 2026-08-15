// net.hpp - RAII POSIX socket wrappers and robust I/O helpers (Linux server).
// STRICT RULE COMPLIANT: no new/delete/malloc. RAII everywhere.
#pragma once

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

namespace lgx {

// RAII file-descriptor owner: the fd is *always* returned to the OS.
class Socket {
public:
    Socket() = default;
    explicit Socket(int fd) noexcept : fd_(fd) {}
    ~Socket() { reset(); }

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    Socket& operator=(Socket&& o) noexcept
    {
        if (this != &o) { reset(); fd_ = o.fd_; o.fd_ = -1; }
        return *this;
    }

    int  get() const noexcept { return fd_; }
    bool valid() const noexcept { return fd_ >= 0; }

    void reset() noexcept
    {
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    }

    // Wake up any thread blocked in recv()/send() on this socket.
    void shutdown_both() noexcept
    {
        if (fd_ >= 0) ::shutdown(fd_, SHUT_RDWR);
    }

private:
    int fd_ = -1;
};

// Send exactly `len` bytes. Handles EINTR and partial writes.
// Returns false on any hard socket error (peer reset, broken pipe, ...).
inline bool send_all(const Socket& s, const void* data, std::size_t len,
                     const std::atomic<bool>* stop = nullptr)
{
    const char* p = static_cast<const char*>(data);
    std::size_t left = len;
    while (left > 0) {
        if (stop != nullptr && stop->load(std::memory_order_relaxed)) return false;
        const ssize_t n = ::send(s.get(), p, left, MSG_NOSIGNAL);
        if (n > 0) { p += n; left -= static_cast<std::size_t>(n); continue; }
        if (n < 0 && (errno == EINTR)) continue;
        return false; // connection lost or fatal error - caller cleans up via RAII
    }
    return true;
}

// Receive exactly `len` bytes. Handles EINTR / partial reads.
// Returns false on EOF or socket error before `len` bytes arrived.
inline bool recv_all(const Socket& s, void* data, std::size_t len,
                     const std::atomic<bool>* stop = nullptr)
{
    char* p = static_cast<char*>(data);
    std::size_t left = len;
    while (left > 0) {
        if (stop != nullptr && stop->load(std::memory_order_relaxed)) return false;
        const ssize_t n = ::recv(s.get(), p, left, 0);
        if (n > 0) { p += n; left -= static_cast<std::size_t>(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        return false; // orderly EOF (n==0) or error - treated as truncated stream
    }
    return true;
}

// Receive up to `cap` bytes (single chunk). Returns -1 on error, 0 on EOF.
inline ssize_t recv_some(const Socket& s, void* data, std::size_t cap)
{
    for (;;) {
        const ssize_t n = ::recv(s.get(), data, cap, 0);
        if (n >= 0) return n;
        if (errno == EINTR) continue;
        return -1;
    }
}

inline void set_io_timeouts(const Socket& s, int seconds)
{
    timeval tv{};
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    ::setsockopt(s.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(s.get(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

} // namespace lgx
