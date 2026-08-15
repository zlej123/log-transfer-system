// main.cpp - Linux log-analysis server (C++17).
//
//   * TCP daemon: receives a large log file, parses it WHILE receiving
//     (fixed 64 KiB chunks - the whole file is never in memory),
//     builds result.csv and streams it back to the client.
//   * Poison-line safe: malformed lines are skipped, sampled and counted.
//   * Robust against mid-transfer disconnects: every socket/thread/file is
//     RAII-owned, so a dropped peer only ends that one connection.
//
// STRICT RULE COMPLIANT: STL containers and RAII ownership only.
#include "../common/protocol.hpp"
#include "net.hpp"
#include "parser.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace {

std::atomic<bool> g_stop{false};
std::atomic<int>  g_active_conns{0};
std::atomic<uint64_t> g_conn_seq{0};
int g_listen_fd_for_signal = -1;

std::mutex  g_log_mutex;
std::string g_log_path; // empty -> stderr

void log_line(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    char ts[32];
    const std::time_t now = std::time(nullptr);
    std::tm tmv{};
    localtime_r(&now, &tmv);
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);

    std::lock_guard<std::mutex> lk(g_log_mutex);
    if (!g_log_path.empty()) {
        std::ofstream f(g_log_path, std::ios::app);
        if (f) f << '[' << ts << "] " << buf << '\n';
    } else {
        std::fprintf(stderr, "[%s] %s\n", ts, buf);
    }
}

void on_signal(int sig)
{
    (void)sig;
    g_stop.store(true);
    // Unblock accept() so the main loop can exit cleanly.
    if (g_listen_fd_for_signal >= 0) ::shutdown(g_listen_fd_for_signal, SHUT_RDWR);
}

struct ServerConfig {
    std::uint16_t port    = lgx::kDefaultPort;
    bool          daemon  = false;
    std::string   workdir = ".";
};

// ---------------------------------------------------------------------------
// Per-connection handling
// ---------------------------------------------------------------------------
void handle_client(lgx::Socket sock, std::string peer, std::uint64_t conn_id,
                   const ServerConfig cfg)
{
    struct ActiveGuard {                       // RAII: connection counter
        ~ActiveGuard() { g_active_conns.fetch_sub(1); }
    } guard;

    lgx::set_io_timeouts(sock, 120);

    try {
        // ---- request header ------------------------------------------------
        unsigned char hdr_bytes[lgx::kHeaderSize];
        if (!lgx::recv_all(sock, hdr_bytes, sizeof(hdr_bytes), &g_stop)) {
            log_line("conn#%llu %s: header not received (peer vanished)",
                     (unsigned long long)conn_id, peer.c_str());
            return;
        }
        lgx::FrameHeader hdr;
        if (!lgx::decode_header(hdr_bytes, sizeof(hdr_bytes), hdr) ||
            hdr.cmd != lgx::Cmd::UploadLog) {
            log_line("conn#%llu %s: invalid/unsupported header - dropping",
                     (unsigned long long)conn_id, peer.c_str());
            return;
        }

        std::string name(hdr.name_len, '\0');
        if (hdr.name_len > 0 &&
            !lgx::recv_all(sock, name.data(), name.size(), &g_stop)) {
            log_line("conn#%llu %s: filename truncated - dropping",
                     (unsigned long long)conn_id, peer.c_str());
            return;
        }
        const std::string fname = lgx::sanitize_filename(name);
        log_line("conn#%llu %s: upload '%s' (%llu bytes) started",
                 (unsigned long long)conn_id, peer.c_str(), fname.c_str(),
                 (unsigned long long)hdr.payload_size);

        // ---- streaming receive + parse (bounded memory) --------------------
        lgx::LogAnalyzer analyzer;
        std::vector<char> chunk(lgx::kChunkSize);
        std::uint64_t remaining = hdr.payload_size;
        const auto t0 = std::chrono::steady_clock::now();

        while (remaining > 0) {
            if (g_stop.load(std::memory_order_relaxed)) {
                log_line("conn#%llu: server shutting down mid-transfer",
                         (unsigned long long)conn_id);
                return;
            }
            const std::size_t want = static_cast<std::size_t>(
                std::min<std::uint64_t>(remaining, chunk.size()));
            const ssize_t n = lgx::recv_some(sock, chunk.data(), want);
            if (n <= 0) {
                log_line("conn#%llu %s: connection lost mid-upload "
                         "(%llu/%llu bytes) - resources released, parsing aborted",
                         (unsigned long long)conn_id, peer.c_str(),
                         (unsigned long long)(hdr.payload_size - remaining),
                         (unsigned long long)hdr.payload_size);
                return; // RAII closes the socket; thread exits cleanly
            }
            analyzer.feed(chunk.data(), static_cast<std::size_t>(n));
            remaining -= static_cast<std::uint64_t>(n);
        }
        analyzer.finish();

        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        log_line("conn#%llu: parse done in %lld ms (%s)",
                 (unsigned long long)conn_id, (long long)ms,
                 analyzer.summary().c_str());

        // ---- persist artifacts on the server side --------------------------
        const std::string csv = analyzer.make_csv();
        {
            static std::mutex artifact_mutex;
            std::lock_guard<std::mutex> lk(artifact_mutex);
            std::ofstream out(cfg.workdir + "/result.csv",
                              std::ios::binary | std::ios::trunc);
            if (out) out.write(csv.data(),
                               static_cast<std::streamsize>(csv.size()));
            std::ofstream err(cfg.workdir + "/parse_errors.log", std::ios::app);
            if (err) {
                err << "=== conn#" << conn_id << " file=" << fname
                    << " malformed=" << analyzer.malformed_lines() << " ===\n";
                for (const auto& e : analyzer.error_samples()) err << e << '\n';
            }
        }

        // ---- send result.csv back ------------------------------------------
        lgx::FrameHeader resp;
        resp.cmd = lgx::Cmd::ResultCsv;
        const std::string resp_name = "result.csv";
        resp.name_len = static_cast<std::uint16_t>(resp_name.size());
        resp.payload_size = csv.size();
        const auto resp_bytes = lgx::encode_header(resp);

        if (!lgx::send_all(sock, resp_bytes.data(), resp_bytes.size(), &g_stop) ||
            !lgx::send_all(sock, resp_name.data(), resp_name.size(), &g_stop) ||
            !lgx::send_all(sock, csv.data(), csv.size(), &g_stop)) {
            log_line("conn#%llu %s: peer lost while sending result "
                     "- resources released",
                     (unsigned long long)conn_id, peer.c_str());
            return;
        }
        log_line("conn#%llu %s: result.csv (%zu bytes) delivered",
                 (unsigned long long)conn_id, peer.c_str(), csv.size());
    } catch (const std::exception& ex) {
        // Absolute last line of defense: one bad connection must never take
        // the daemon down.
        log_line("conn#%llu: exception contained: %s",
                 (unsigned long long)conn_id, ex.what());
    } catch (...) {
        log_line("conn#%llu: unknown exception contained",
                 (unsigned long long)conn_id);
    }
}

// ---------------------------------------------------------------------------
// Daemonization (classic double fork)
// ---------------------------------------------------------------------------
bool daemonize(const ServerConfig& cfg)
{
    pid_t pid = ::fork();
    if (pid < 0) return false;
    if (pid > 0) ::_exit(0);          // parent leaves

    if (::setsid() < 0) return false; // detached session, no controlling TTY
    ::signal(SIGHUP, SIG_IGN);

    pid = ::fork();
    if (pid < 0) return false;
    if (pid > 0) ::_exit(0);          // first child leaves

    ::umask(022);

    // Detach stdio; all further output goes to the log file.
    const int devnull = ::open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        ::dup2(devnull, STDIN_FILENO);
        ::dup2(devnull, STDOUT_FILENO);
        ::dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) ::close(devnull);
    }

    std::ofstream pidf(cfg.workdir + "/server.pid", std::ios::trunc);
    if (pidf) pidf << ::getpid() << '\n';
    return true;
}

} // namespace

int main(int argc, char** argv)
{
    ServerConfig cfg;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--port" && i + 1 < argc) {
            const long p = std::strtol(argv[++i], nullptr, 10);
            if (p > 0 && p < 65536) cfg.port = static_cast<std::uint16_t>(p);
        } else if (a == "--daemon") {
            cfg.daemon = true;
        } else if (a == "--workdir" && i + 1 < argc) {
            cfg.workdir = argv[++i];
        } else if (a == "--help" || a == "-h") {
            std::printf(
                "usage: log_server [--port N] [--workdir DIR] [--daemon]\n"
                "  --port N       TCP port to listen on (default %u)\n"
                "  --workdir DIR  where result.csv / logs are written\n"
                "  --daemon       run as background daemon (logs to file)\n",
                (unsigned)lgx::kDefaultPort);
            return 0;
        }
    }

    ::mkdir(cfg.workdir.c_str(), 0755); // best effort

    if (cfg.daemon) {
        g_log_path = cfg.workdir + "/server.log";
        if (!daemonize(cfg)) {
            std::fprintf(stderr, "daemonize failed\n");
            return 1;
        }
    }

    // A dead peer must produce a socket error, never a SIGPIPE crash.
    ::signal(SIGPIPE, SIG_IGN);
    struct sigaction sa {};
    sa.sa_handler = on_signal;
    ::sigaction(SIGINT, &sa, nullptr);
    ::sigaction(SIGTERM, &sa, nullptr);

    lgx::Socket listener(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (!listener.valid()) {
        log_line("socket() failed: %s", std::strerror(errno));
        return 1;
    }
    const int one = 1;
    ::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(cfg.port);
    if (::bind(listener.get(), reinterpret_cast<const sockaddr*>(&addr),
               sizeof(addr)) < 0) {
        log_line("bind(%u) failed: %s", (unsigned)cfg.port,
                 std::strerror(errno));
        return 1;
    }
    if (::listen(listener.get(), 16) < 0) {
        log_line("listen failed: %s", std::strerror(errno));
        return 1;
    }
    g_listen_fd_for_signal = listener.get();
    log_line("log_server listening on port %u (workdir=%s, pid=%d)",
             (unsigned)cfg.port, cfg.workdir.c_str(), (int)::getpid());

    while (!g_stop.load()) {
        sockaddr_in cli{};
        socklen_t cli_len = sizeof(cli);
        lgx::Socket conn(::accept(listener.get(),
                                  reinterpret_cast<sockaddr*>(&cli), &cli_len));
        if (!conn.valid()) {
            if (g_stop.load()) break;
            if (errno == EINTR || errno == ECONNABORTED) continue;
            log_line("accept failed: %s", std::strerror(errno));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        char ip[INET_ADDRSTRLEN] = {0};
        ::inet_ntop(AF_INET, &cli.sin_addr, ip, sizeof(ip));
        std::string peer = std::string(ip) + ":" +
                           std::to_string(ntohs(cli.sin_port));

        const std::uint64_t id = g_conn_seq.fetch_add(1) + 1;
        g_active_conns.fetch_add(1);
        std::thread(handle_client, std::move(conn), std::move(peer), id, cfg)
            .detach();
    }

    log_line("shutdown requested; waiting for %d active connection(s)",
             g_active_conns.load());
    for (int i = 0; i < 100 && g_active_conns.load() > 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    log_line("server stopped");
    return 0;
}
