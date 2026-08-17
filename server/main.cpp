// Linux TLS log-analysis daemon with bounded workers and resumable uploads.
#include "../common/protocol.hpp"
#include "../common/tls.hpp"
#include "file_io.hpp"
#include "net.hpp"
#include "parser.hpp"
#include "thread_pool.hpp"
#include "upload_store.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace {

std::atomic<bool> g_stop{false};
std::atomic<std::uint64_t> g_connection_sequence{0};
std::mutex g_log_mutex;
std::string g_log_path;

void log_line(const char* format, ...)
{
    char message[1024]{};
    va_list args;
    va_start(args, format);
    std::vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    char timestamp[32]{};
    const std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_r(&now, &local);
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &local);

    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_path.empty()) {
        std::fprintf(stderr, "[%s] %s\n", timestamp, message);
    } else {
        std::ofstream out(g_log_path, std::ios::app);
        if (out) out << '[' << timestamp << "] " << message << '\n';
    }
}

struct ServerConfig {
    std::uint16_t port = lgx::kDefaultPort;
    bool daemon = false;
    std::filesystem::path workdir = ".";
    std::filesystem::path cert = "certs/server.crt";
    std::filesystem::path key = "certs/server.key";
    std::filesystem::path client_ca = "certs/ca.crt";
    std::string allowed_client_subject = "CN=lgx-client";
    std::size_t threads = 4;
    std::size_t queue_capacity = 32;
    std::uint64_t max_reserved_bytes = 20ull * 1024 * 1024 * 1024;
    std::size_t max_partials = 100;
    // Durable checkpoint interval. Each checkpoint costs fdatasync(spool) plus a
    // synced manifest replace, so this trades steady-state upload throughput
    // against how much of an interrupted upload must be resent.
    std::uint64_t checkpoint_bytes = 16ull * 1024 * 1024;
    int resume_ttl_hours = 24;
    bool log_poison_samples = false;
};

struct ConnectionState {
    explicit ConnectionState(lgx::Socket socket_value)
        : socket(std::move(socket_value)) {}
    lgx::Socket socket;
};

struct ConnectionTask {
    using ConnectionType = ConnectionState;
    std::shared_ptr<ConnectionState> connection;
    std::string peer;
    std::uint64_t id = 0;
    std::chrono::steady_clock::time_point accepted_at;
};

bool send_error(lgx::TlsSession& tls, lgx::ErrorCode code,
                const std::string& raw_message)
{
    std::string message = raw_message.substr(0, static_cast<std::size_t>(lgx::kMaxErrorSize));
    lgx::FrameHeader header;
    header.cmd = lgx::Cmd::ErrorText;
    header.flags = static_cast<std::uint8_t>(code);
    header.payload_size = message.size();
    const auto bytes = lgx::encode_header(header);
    return tls.send_all(bytes.data(), bytes.size(), &g_stop) &&
           tls.send_all(message.data(), message.size(), &g_stop);
}

bool hash_and_analyze(const std::filesystem::path& path,
                      lgx::Sha256Digest& digest, lgx::LogAnalyzer& analyzer,
                      const std::atomic<bool>& stop, std::string& error)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) { error = "cannot open completed spool"; return false; }
    lgx::Sha256 hash;
    std::vector<char> chunk(lgx::kChunkSize);
    while (input) {
        if (stop.load(std::memory_order_relaxed)) {
            error = "analysis cancelled for shutdown";
            return false;
        }
        input.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        const std::streamsize count = input.gcount();
        if (count > 0) {
            if (!hash.update(chunk.data(), static_cast<std::size_t>(count))) {
                error = "SHA-256 update failed";
                return false;
            }
            analyzer.feed(chunk.data(), static_cast<std::size_t>(count));
        }
    }
    if (!input.eof()) { error = "completed spool read failed"; return false; }
    analyzer.finish();
    if (!hash.finish(digest)) { error = "SHA-256 finish failed"; return false; }
    return true;
}

lgx::Sha256Digest hash_bytes(const std::string& data)
{
    lgx::Sha256Digest digest{};
    lgx::Sha256 hash;
    hash.update(data.data(), data.size());
    hash.finish(digest);
    return digest;
}

void handle_connection(ConnectionTask task, const ServerConfig& config,
                       lgx::UploadStore& store)
{
    const auto connection = task.connection;
    lgx::set_io_timeouts(connection->socket, 1);
    try {
        lgx::TlsServerConfig tls_config;
        std::string error;
        if (!tls_config.setup(config.cert.string(), config.key.string(),
                              config.client_ca.string(), error)) {
            log_line("conn#%llu TLS configuration failed: %s",
                     (unsigned long long)task.id, error.c_str());
            return;
        }
        lgx::TlsSession tls;
        if (!tls.setup(tls_config.raw(), connection->socket.get(), {}, error) ||
            !tls.handshake(&g_stop, error)) {
            log_line("conn#%llu %s TLS handshake rejected: %s",
                     (unsigned long long)task.id, task.peer.c_str(), error.c_str());
            return;
        }
        const std::string client_subject = tls.peer_subject();
        if (tls.verify_result() != 0 || !tls.alpn_is_lgx2() ||
            client_subject != config.allowed_client_subject) {
            log_line("conn#%llu %s client identity/ALPN rejected",
                     (unsigned long long)task.id, task.peer.c_str());
            return;
        }
        log_line("conn#%llu %s TLS=%s client=%s",
                 (unsigned long long)task.id, task.peer.c_str(), tls.version(),
                 client_subject.c_str());

        unsigned char header_bytes[lgx::kHeaderSize]{};
        if (!tls.recv_all(header_bytes, sizeof(header_bytes), &g_stop, 10)) return;
        lgx::FrameHeader header;
        if (!lgx::decode_header(header_bytes, sizeof(header_bytes), header) ||
            header.cmd != lgx::Cmd::UploadInit) {
            send_error(tls, lgx::ErrorCode::Protocol, "invalid LGX2 upload header");
            return;
        }

        std::string raw_name(header.name_len, '\0');
        lgx::Sha256Digest claimed_digest{};
        lgx::ResumeToken requested_token{};
        if ((header.name_len > 0 &&
             !tls.recv_all(raw_name.data(), raw_name.size(), &g_stop, 10)) ||
            !tls.recv_all(claimed_digest.data(), claimed_digest.size(), &g_stop, 10) ||
            !tls.recv_all(requested_token.data(), requested_token.size(), &g_stop, 10)) {
            return;
        }
        const std::string name = lgx::sanitize_filename(raw_name);
        bool has_token = false;
        for (unsigned char c : requested_token) has_token = has_token || c != 0;

        auto lease_option = store.begin(claimed_digest, requested_token,
                                        header.payload_size, name,
                                        client_subject, error);
        if (!lease_option) {
            const lgx::ErrorCode code = error == "upload currently active"
                ? lgx::ErrorCode::ServerBusy
                : (has_token ? lgx::ErrorCode::ResumeInvalid
                             : lgx::ErrorCode::Storage);
            send_error(tls, code, error);
            return;
        }
        lgx::UploadLease lease = std::move(*lease_option);
        lgx::UploadRecord& upload = lease.record();

        lgx::FrameHeader resume;
        resume.cmd = lgx::Cmd::ResumeInfo;
        resume.payload_size = upload.offset;
        const auto resume_bytes = lgx::encode_header(resume);
        if (!tls.send_all(resume_bytes.data(), resume_bytes.size(), &g_stop) ||
            !tls.send_all(upload.token.data(), upload.token.size(), &g_stop))
            return;

        log_line("conn#%llu upload=%s file='%s' resume=%llu/%llu",
                 (unsigned long long)task.id,
                 lgx::hex_encode(upload.token.data(), 8).c_str(), name.c_str(),
                 (unsigned long long)upload.offset,
                 (unsigned long long)upload.total_size);

        std::string csv;
        if (upload.complete) {
            csv = store.read_result(upload, error);
            if (!error.empty()) {
                if (!store.discard(upload))
                    log_line("conn#%llu invalid cache retained for quota accounting",
                             (unsigned long long)task.id);
                send_error(tls, lgx::ErrorCode::ResumeInvalid,
                           "completed result cache failed integrity validation");
                return;
            }
        } else {
            lgx::FileHandle spool(::open(upload.part_path.c_str(),
                O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600));
            if (!spool.valid() ||
                ::lseek(spool.get(), static_cast<off_t>(upload.offset), SEEK_SET) < 0) {
                send_error(tls, lgx::ErrorCode::Storage,
                           "cannot open partial upload storage");
                return;
            }
            lgx::set_io_timeouts(connection->socket, 1);
            std::vector<char> chunk(lgx::kChunkSize);
            std::uint64_t current_offset = upload.offset;
            std::uint64_t since_checkpoint = 0;
            const auto started = std::chrono::steady_clock::now();
            const auto overall_limit = std::chrono::seconds(
                std::max<std::uint64_t>(300, upload.total_size / (1024 * 1024) + 60));
            while (current_offset < upload.total_size) {
                if (g_stop.load()) return;
                const std::size_t want = static_cast<std::size_t>(
                    std::min<std::uint64_t>(upload.total_size - current_offset,
                                            chunk.size()));
                const std::int64_t count = tls.recv_some(
                    chunk.data(), want, &g_stop, 30);
                if (count <= 0) {
                    if (spool.sync_data())
                        store.checkpoint(upload, current_offset, error);
                    log_line("conn#%llu interrupted at durable offset %llu; resumable state retained",
                             (unsigned long long)task.id,
                             (unsigned long long)upload.offset);
                    return;
                }
                if (!spool.write_all(chunk.data(), static_cast<std::size_t>(count))) {
                    send_error(tls, lgx::ErrorCode::Storage,
                               "partial upload write failed");
                    return;
                }
                current_offset += static_cast<std::uint64_t>(count);
                since_checkpoint += static_cast<std::uint64_t>(count);
                if (since_checkpoint >= config.checkpoint_bytes) {
                    if (!spool.sync_data() ||
                        !store.checkpoint(upload, current_offset, error)) {
                        send_error(tls, lgx::ErrorCode::Storage,
                                   error.empty() ? "durable checkpoint failed" : error);
                        return;
                    }
                    since_checkpoint = 0;
                }
                if (std::chrono::steady_clock::now() - started > overall_limit) {
                    if (spool.sync_data())
                        store.checkpoint(upload, current_offset, error);
                    send_error(tls, lgx::ErrorCode::Protocol,
                               "upload exceeded its absolute deadline");
                    return;
                }
            }
            if (!spool.sync_data() ||
                !store.checkpoint(upload, current_offset, error)) {
                send_error(tls, lgx::ErrorCode::Storage,
                           error.empty() ? "final durable checkpoint failed" : error);
                return;
            }
            spool.reset();

            lgx::Sha256Digest actual_digest{};
            lgx::LogAnalyzer analyzer;
            const auto parse_started = std::chrono::steady_clock::now();
            if (!hash_and_analyze(upload.part_path, actual_digest, analyzer,
                                  g_stop, error)) {
                if (!g_stop.load())
                    send_error(tls, lgx::ErrorCode::Storage, error);
                return;
            }
            if (!lgx::digest_equal(actual_digest, upload.digest)) {
                if (!store.discard(upload))
                    log_line("conn#%llu checksum-failed spool retained for quota accounting",
                             (unsigned long long)task.id);
                send_error(tls, lgx::ErrorCode::ChecksumMismatch,
                           "uploaded file SHA-256 mismatch; partial state discarded");
                return;
            }
            if (g_stop.load()) return;
            csv = analyzer.make_csv();
            if (g_stop.load()) return;
            if (csv.size() > lgx::kMaxResultSize) {
                send_error(tls, lgx::ErrorCode::Internal,
                           "analysis result exceeds configured protocol cap");
                return;
            }
            if (!store.mark_complete(upload, csv, error)) {
                send_error(tls, lgx::ErrorCode::Storage, error);
                return;
            }
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - parse_started).count();
            log_line("conn#%llu verified SHA-256 and analyzed in %lld ms (%s)",
                     (unsigned long long)task.id, (long long)elapsed,
                     analyzer.summary().c_str());
            if (config.log_poison_samples && !analyzer.error_samples().empty()) {
                const auto error_path = std::filesystem::path(
                    upload.meta_path.parent_path() /
                    (upload.meta_path.stem().string() + ".errors.log"));
                std::ofstream poison_log(error_path, std::ios::trunc);
                for (const auto& sample : analyzer.error_samples())
                    poison_log << sample << '\n';
            }
        }

        const lgx::Sha256Digest result_digest = hash_bytes(csv);
        const std::string result_name = "result.csv";
        lgx::FrameHeader result;
        result.cmd = lgx::Cmd::ResultCsv;
        result.name_len = static_cast<std::uint16_t>(result_name.size());
        result.payload_size = csv.size();
        const auto result_bytes = lgx::encode_header(result);
        if (!tls.send_all(result_bytes.data(), result_bytes.size(), &g_stop) ||
            !tls.send_all(result_name.data(), result_name.size(), &g_stop) ||
            !tls.send_all(result_digest.data(), result_digest.size(), &g_stop) ||
            !tls.send_all(csv.data(), csv.size(), &g_stop)) {
            log_line("conn#%llu result delivery interrupted; cached result retained",
                     (unsigned long long)task.id);
            return;
        }
        tls.close_notify();
        log_line("conn#%llu result delivered (%zu bytes)",
                 (unsigned long long)task.id, csv.size());
    } catch (const std::exception& ex) {
        log_line("conn#%llu exception contained: %s",
                 (unsigned long long)task.id, ex.what());
    } catch (...) {
        log_line("conn#%llu unknown exception contained",
                 (unsigned long long)task.id);
    }
}

bool daemonize()
{
    pid_t pid = ::fork();
    if (pid < 0) return false;
    if (pid > 0) ::_exit(0);
    if (::setsid() < 0) return false;
    ::signal(SIGHUP, SIG_IGN);
    pid = ::fork();
    if (pid < 0) return false;
    if (pid > 0) ::_exit(0);
    ::umask(077);
    const int null_fd = ::open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd >= 0) {
        ::dup2(null_fd, STDIN_FILENO);
        ::dup2(null_fd, STDOUT_FILENO);
        ::dup2(null_fd, STDERR_FILENO);
        if (null_fd > STDERR_FILENO) ::close(null_fd);
    }
    return true;
}

bool prepare_private_directory(const std::filesystem::path& path)
{
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    if (ec) return false;
    const auto absolute = std::filesystem::absolute(path, ec).lexically_normal();
    if (ec) return false;
    std::filesystem::path current;
    for (const auto& component : absolute) {
        current /= component;
        struct stat component_info {};
        if (::lstat(current.c_str(), &component_info) != 0 ||
            S_ISLNK(component_info.st_mode))
            return false;
    }
    struct stat final_info {};
    if (::lstat(absolute.c_str(), &final_info) != 0 ||
        !S_ISDIR(final_info.st_mode) || final_info.st_uid != ::geteuid())
        return false;
    return ::chmod(absolute.c_str(), 0700) == 0;
}

} // namespace

int main(int argc, char** argv)
{
    ServerConfig config;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--port" && i + 1 < argc) {
            const long value = std::strtol(argv[++i], nullptr, 10);
            if (value >= 0 && value < 65536)
                config.port = static_cast<std::uint16_t>(value);
        } else if (argument == "--workdir" && i + 1 < argc) {
            config.workdir = argv[++i];
        } else if (argument == "--cert" && i + 1 < argc) {
            config.cert = argv[++i];
        } else if (argument == "--key" && i + 1 < argc) {
            config.key = argv[++i];
        } else if (argument == "--client-ca" && i + 1 < argc) {
            config.client_ca = argv[++i];
        } else if (argument == "--allowed-client-subject" && i + 1 < argc) {
            config.allowed_client_subject = argv[++i];
        } else if (argument == "--threads" && i + 1 < argc) {
            config.threads = static_cast<std::size_t>(std::max(1, std::atoi(argv[++i])));
        } else if (argument == "--queue" && i + 1 < argc) {
            config.queue_capacity = static_cast<std::size_t>(std::max(1, std::atoi(argv[++i])));
        } else if (argument == "--max-storage-gb" && i + 1 < argc) {
            config.max_reserved_bytes = static_cast<std::uint64_t>(
                std::max(1, std::atoi(argv[++i]))) * 1024ull * 1024 * 1024;
        } else if (argument == "--checkpoint-mb" && i + 1 < argc) {
            config.checkpoint_bytes = static_cast<std::uint64_t>(
                std::max(1, std::atoi(argv[++i]))) * 1024ull * 1024;
        } else if (argument == "--max-partials" && i + 1 < argc) {
            config.max_partials = static_cast<std::size_t>(std::max(1, std::atoi(argv[++i])));
        } else if (argument == "--resume-ttl-hours" && i + 1 < argc) {
            config.resume_ttl_hours = std::max(1, std::atoi(argv[++i]));
        } else if (argument == "--log-poison-samples") {
            config.log_poison_samples = true;
        } else if (argument == "--daemon") {
            config.daemon = true;
        } else if (argument == "--help" || argument == "-h") {
            std::printf(
                "usage: log_server [options]\n"
                "  --port N --workdir DIR --daemon\n"
                "  --cert FILE --key FILE --client-ca FILE\n"
                "  --allowed-client-subject DN\n"
                "  --threads N --queue N --max-storage-gb N --max-partials N\n"
                "  --resume-ttl-hours N --checkpoint-mb N --log-poison-samples\n");
            return 0;
        }
    }

    ::umask(077);
    if (!prepare_private_directory(config.workdir) ||
        !prepare_private_directory(config.workdir / "uploads")) {
        std::fprintf(stderr, "workdir must be a private, non-symlink directory\n");
        return 1;
    }
    lgx::FileHandle work_lock(::open(
        (config.workdir / ".server.lock").c_str(),
        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (!work_lock.valid() || ::flock(work_lock.get(), LOCK_EX | LOCK_NB) != 0) {
        std::fprintf(stderr, "workdir is already owned by another server process\n");
        return 1;
    }
    if (config.daemon) {
        g_log_path = (config.workdir / "server.log").string();
        if (!daemonize()) return 1;
    }

    ::signal(SIGPIPE, SIG_IGN);
    sigset_t signal_mask;
    ::sigemptyset(&signal_mask);
    ::sigaddset(&signal_mask, SIGINT);
    ::sigaddset(&signal_mask, SIGTERM);
    if (::pthread_sigmask(SIG_BLOCK, &signal_mask, nullptr) != 0) {
        log_line("cannot block shutdown signals");
        return 1;
    }
    lgx::Socket signal_fd(::signalfd(-1, &signal_mask, SFD_CLOEXEC | SFD_NONBLOCK));
    if (!signal_fd.valid()) {
        log_line("signalfd failed: %s", std::strerror(errno));
        return 1;
    }

    std::string tls_probe_error;
    lgx::TlsServerConfig tls_probe;
    if (!tls_probe.setup(config.cert.string(), config.key.string(),
                         config.client_ca.string(), tls_probe_error)) {
        log_line("TLS startup validation failed: %s", tls_probe_error.c_str());
        return 1;
    }

    lgx::UploadStore store(config.workdir / "uploads",
                           config.max_reserved_bytes, config.max_partials,
                           std::chrono::hours(config.resume_ttl_hours));

    lgx::Socket listener(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (!listener.valid()) return 1;
    const int enabled = 1;
    ::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(config.port);
    if (::bind(listener.get(), reinterpret_cast<const sockaddr*>(&address),
               sizeof(address)) < 0 || ::listen(listener.get(), 64) < 0) {
        log_line("listen setup failed: %s", std::strerror(errno));
        return 1;
    }

    if (config.port == 0) {
        sockaddr_in bound{};
        socklen_t bound_len = sizeof(bound);
        if (::getsockname(listener.get(), reinterpret_cast<sockaddr*>(&bound),
                          &bound_len) != 0)
            return 1;
        config.port = ntohs(bound.sin_port);
    }
    {
        std::ofstream port_file(config.workdir / "server.port", std::ios::trunc);
        if (!port_file) return 1;
        port_file << config.port << '\n';
        port_file.flush();
        if (!port_file) return 1;
    }

    if (config.daemon) {
        std::ofstream pid_file(config.workdir / "server.pid", std::ios::trunc);
        if (!pid_file) return 1;
        pid_file << ::getpid() << '\n';
        pid_file.flush();
        if (!pid_file) return 1;
    }

    lgx::BoundedThreadPool<ConnectionTask> pool(
        config.threads, config.queue_capacity, std::chrono::seconds(10),
        [&config, &store](ConnectionTask task) {
            handle_connection(std::move(task), config, store);
        });

    log_line("TLS log_server port=%u workers=%zu queue=%zu workdir=%s pid=%d",
             (unsigned)config.port, config.threads, config.queue_capacity,
             config.workdir.c_str(), (int)::getpid());

    auto last_overload_log = std::chrono::steady_clock::time_point{};
    while (!g_stop.load()) {
        pollfd fds[2]{};
        fds[0].fd = listener.get(); fds[0].events = POLLIN;
        fds[1].fd = signal_fd.get(); fds[1].events = POLLIN;
        const int ready = ::poll(fds, 2, 1000);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if ((fds[1].revents & POLLIN) != 0) {
            signalfd_siginfo info{};
            const ssize_t signal_bytes =
                ::read(signal_fd.get(), &info, sizeof(info));
            (void)signal_bytes;
            g_stop.store(true);
            break;
        }
        if ((fds[0].revents & POLLIN) == 0) continue;

        constexpr int kAcceptBatch = 64;
        for (int accepted = 0; accepted < kAcceptBatch; ++accepted) {
            sockaddr_in client{};
            socklen_t client_len = sizeof(client);
            lgx::Socket socket(::accept4(
                listener.get(), reinterpret_cast<sockaddr*>(&client), &client_len,
                SOCK_CLOEXEC));
            if (!socket.valid()) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR || errno == ECONNABORTED) continue;
                log_line("accept failed: %s", std::strerror(errno));
                break;
            }
            char ip[INET_ADDRSTRLEN]{};
            ::inet_ntop(AF_INET, &client.sin_addr, ip, sizeof(ip));
            auto connection = std::make_shared<ConnectionState>(std::move(socket));
            ConnectionTask task;
            task.connection = std::move(connection);
            task.peer = std::string(ip) + ':' + std::to_string(ntohs(client.sin_port));
            task.id = g_connection_sequence.fetch_add(1) + 1;
            task.accepted_at = std::chrono::steady_clock::now();
            if (!pool.try_submit(std::move(task))) {
                const auto now = std::chrono::steady_clock::now();
                if (now - last_overload_log >= std::chrono::seconds(1)) {
                    log_line("connection rejected: bounded queue full");
                    last_overload_log = now;
                }
            }
        }
    }

    g_stop.store(true);
    listener.reset();
    log_line("shutdown: closing queue and active TLS sessions");
    pool.stop();
    std::error_code remove_error;
    std::filesystem::remove(config.workdir / "server.pid", remove_error);
    std::filesystem::remove(config.workdir / "server.port", remove_error);
    log_line("server stopped");
    return 0;
}
