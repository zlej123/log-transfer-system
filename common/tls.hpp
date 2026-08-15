// TLS 1.3 transport wrappers backed by vendored Mbed TLS.
#pragma once

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  using TlsNativeSocket = SOCKET;
#else
  #include <cerrno>
  #include <sys/socket.h>
  #include <unistd.h>
  using TlsNativeSocket = int;
#endif

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

namespace lgx {

inline std::string tls_error_text(int code)
{
    char text[256]{};
    mbedtls_strerror(code, text, sizeof(text));
    return std::string(text);
}

class TlsServerConfig {
public:
    TlsServerConfig()
    {
        mbedtls_entropy_init(&entropy_);
        mbedtls_ctr_drbg_init(&rng_);
        mbedtls_x509_crt_init(&cert_);
        mbedtls_x509_crt_init(&client_ca_);
        mbedtls_pk_init(&key_);
        mbedtls_ssl_config_init(&config_);
    }
    ~TlsServerConfig()
    {
        mbedtls_ssl_config_free(&config_);
        mbedtls_pk_free(&key_);
        mbedtls_x509_crt_free(&client_ca_);
        mbedtls_x509_crt_free(&cert_);
        mbedtls_ctr_drbg_free(&rng_);
        mbedtls_entropy_free(&entropy_);
    }

    bool setup(const std::string& cert_file, const std::string& key_file,
               const std::string& client_ca_file, std::string& error)
    {
        static constexpr unsigned char kPersonal[] = "lgx-server-tls";
        int rc = mbedtls_ctr_drbg_seed(&rng_, mbedtls_entropy_func, &entropy_,
                                       kPersonal, sizeof(kPersonal) - 1);
        if (rc != 0) return fail("TLS RNG seed", rc, error);
        rc = mbedtls_x509_crt_parse_file(&cert_, cert_file.c_str());
        if (rc != 0) return fail("server certificate", rc, error);
        rc = mbedtls_x509_crt_parse_file(&client_ca_, client_ca_file.c_str());
        if (rc != 0) return fail("client CA certificate", rc, error);
        rc = mbedtls_pk_parse_keyfile(&key_, key_file.c_str(), nullptr,
                                      mbedtls_ctr_drbg_random, &rng_);
        if (rc != 0) return fail("server private key", rc, error);
        rc = mbedtls_pk_check_pair(&cert_.pk, &key_,
                                   mbedtls_ctr_drbg_random, &rng_);
        if (rc != 0) return fail("server certificate/key pair", rc, error);
        rc = mbedtls_ssl_config_defaults(&config_, MBEDTLS_SSL_IS_SERVER,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT);
        if (rc != 0) return fail("server TLS defaults", rc, error);
        mbedtls_ssl_conf_min_tls_version(&config_,
                                         MBEDTLS_SSL_VERSION_TLS1_3);
        mbedtls_ssl_conf_rng(&config_, mbedtls_ctr_drbg_random, &rng_);
        mbedtls_ssl_conf_authmode(&config_, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&config_, &client_ca_, nullptr);
        static const char* kAlpn[] = {"lgx/2", nullptr};
        rc = mbedtls_ssl_conf_alpn_protocols(&config_, kAlpn);
        if (rc != 0) return fail("server ALPN", rc, error);
        rc = mbedtls_ssl_conf_own_cert(&config_, &cert_, &key_);
        if (rc != 0) return fail("server certificate binding", rc, error);
        return true;
    }

    mbedtls_ssl_config* raw() { return &config_; }

private:
    TlsServerConfig(const TlsServerConfig&);
    TlsServerConfig& operator=(const TlsServerConfig&);

    static bool fail(const char* where, int rc, std::string& error)
    {
        error = std::string(where) + ": " + tls_error_text(rc);
        return false;
    }

    mbedtls_entropy_context entropy_{};
    mbedtls_ctr_drbg_context rng_{};
    mbedtls_x509_crt cert_{};
    mbedtls_x509_crt client_ca_{};
    mbedtls_pk_context key_{};
    mbedtls_ssl_config config_{};
};

class TlsClientConfig {
public:
    TlsClientConfig()
    {
        mbedtls_entropy_init(&entropy_);
        mbedtls_ctr_drbg_init(&rng_);
        mbedtls_x509_crt_init(&ca_);
        mbedtls_x509_crt_init(&cert_);
        mbedtls_pk_init(&key_);
        mbedtls_ssl_config_init(&config_);
    }
    ~TlsClientConfig()
    {
        mbedtls_ssl_config_free(&config_);
        mbedtls_pk_free(&key_);
        mbedtls_x509_crt_free(&cert_);
        mbedtls_x509_crt_free(&ca_);
        mbedtls_ctr_drbg_free(&rng_);
        mbedtls_entropy_free(&entropy_);
    }

    bool setup(const std::string& ca_file, const std::string& cert_file,
               const std::string& key_file, std::string& error)
    {
        static constexpr unsigned char kPersonal[] = "lgx-client-tls";
        int rc = mbedtls_ctr_drbg_seed(&rng_, mbedtls_entropy_func, &entropy_,
                                       kPersonal, sizeof(kPersonal) - 1);
        if (rc != 0) return fail("TLS RNG seed", rc, error);
        rc = mbedtls_x509_crt_parse_file(&ca_, ca_file.c_str());
        if (rc != 0) return fail("CA certificate", rc, error);
        rc = mbedtls_x509_crt_parse_file(&cert_, cert_file.c_str());
        if (rc != 0) return fail("client certificate", rc, error);
        rc = mbedtls_pk_parse_keyfile(&key_, key_file.c_str(), nullptr,
                                      mbedtls_ctr_drbg_random, &rng_);
        if (rc != 0) return fail("client private key", rc, error);
        rc = mbedtls_pk_check_pair(&cert_.pk, &key_,
                                   mbedtls_ctr_drbg_random, &rng_);
        if (rc != 0) return fail("client certificate/key pair", rc, error);
        rc = mbedtls_ssl_config_defaults(&config_, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT);
        if (rc != 0) return fail("client TLS defaults", rc, error);
        mbedtls_ssl_conf_min_tls_version(&config_,
                                         MBEDTLS_SSL_VERSION_TLS1_3);
        mbedtls_ssl_conf_authmode(&config_, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&config_, &ca_, nullptr);
        mbedtls_ssl_conf_rng(&config_, mbedtls_ctr_drbg_random, &rng_);
        rc = mbedtls_ssl_conf_own_cert(&config_, &cert_, &key_);
        if (rc != 0) return fail("client certificate binding", rc, error);
        static const char* kAlpn[] = {"lgx/2", nullptr};
        rc = mbedtls_ssl_conf_alpn_protocols(&config_, kAlpn);
        if (rc != 0) return fail("client ALPN", rc, error);
        return true;
    }

    mbedtls_ssl_config* raw() { return &config_; }

private:
    TlsClientConfig(const TlsClientConfig&);
    TlsClientConfig& operator=(const TlsClientConfig&);

    static bool fail(const char* where, int rc, std::string& error)
    {
        error = std::string(where) + ": " + tls_error_text(rc);
        return false;
    }

    mbedtls_entropy_context entropy_{};
    mbedtls_ctr_drbg_context rng_{};
    mbedtls_x509_crt ca_{};
    mbedtls_x509_crt cert_{};
    mbedtls_pk_context key_{};
    mbedtls_ssl_config config_{};
};

class TlsSession {
public:
    TlsSession() { mbedtls_ssl_init(&ssl_); }
    ~TlsSession() { mbedtls_ssl_free(&ssl_); }

    bool setup(mbedtls_ssl_config* config, TlsNativeSocket socket,
               const std::string& expected_name, std::string& error)
    {
        socket_ = socket;
        int rc = mbedtls_ssl_setup(&ssl_, config);
        if (rc != 0) return fail("TLS session setup", rc, error);
        if (!expected_name.empty()) {
            rc = mbedtls_ssl_set_hostname(&ssl_, expected_name.c_str());
            if (rc != 0) return fail("TLS expected name", rc, error);
        }
        mbedtls_ssl_set_bio(&ssl_, &socket_, socket_send, socket_recv, nullptr);
        return true;
    }

    bool handshake(const std::atomic<bool>* stop, std::string& error,
                   int timeout_seconds = 15)
    {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(timeout_seconds);
        for (;;) {
            if ((stop != nullptr && stop->load(std::memory_order_relaxed)) ||
                std::chrono::steady_clock::now() >= deadline) {
                error = "TLS handshake cancelled or timed out";
                return false;
            }
            const int rc = mbedtls_ssl_handshake(&ssl_);
            if (rc == 0) return true;
            if (rc == MBEDTLS_ERR_SSL_WANT_READ ||
                rc == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;
            return fail("TLS handshake", rc, error);
        }
    }

    bool send_all(const void* data, std::size_t len,
                  const std::atomic<bool>* stop = nullptr,
                  int timeout_seconds = 300)
    {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(timeout_seconds);
        const unsigned char* p = static_cast<const unsigned char*>(data);
        std::size_t left = len;
        while (left > 0) {
            if ((stop != nullptr && stop->load(std::memory_order_relaxed)) ||
                std::chrono::steady_clock::now() >= deadline)
                return false;
            const int rc = mbedtls_ssl_write(&ssl_, p, left);
            if (rc > 0) {
                p += rc;
                left -= static_cast<std::size_t>(rc);
                continue;
            }
            if (rc == MBEDTLS_ERR_SSL_WANT_READ ||
                rc == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;
            return false;
        }
        return true;
    }

    bool recv_all(void* data, std::size_t len,
                  const std::atomic<bool>* stop = nullptr,
                  int timeout_seconds = 300)
    {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(timeout_seconds);
        unsigned char* p = static_cast<unsigned char*>(data);
        std::size_t left = len;
        while (left > 0) {
            if ((stop != nullptr && stop->load(std::memory_order_relaxed)) ||
                std::chrono::steady_clock::now() >= deadline)
                return false;
            const int rc = mbedtls_ssl_read(&ssl_, p, left);
            if (rc > 0) {
                p += rc;
                left -= static_cast<std::size_t>(rc);
                continue;
            }
            if (rc == MBEDTLS_ERR_SSL_WANT_READ ||
                rc == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;
            return false;
        }
        return true;
    }

    std::int64_t recv_some(void* data, std::size_t cap,
                           const std::atomic<bool>* stop = nullptr,
                           int timeout_seconds = 30)
    {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(timeout_seconds);
        for (;;) {
            if ((stop != nullptr && stop->load(std::memory_order_relaxed)) ||
                std::chrono::steady_clock::now() >= deadline)
                return -1;
            const int rc = mbedtls_ssl_read(
                &ssl_, static_cast<unsigned char*>(data), cap);
            if (rc > 0) return rc;
            if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
                return 0;
            if (rc == MBEDTLS_ERR_SSL_WANT_READ ||
                rc == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;
            return -1;
        }
    }

    void close_notify() noexcept
    {
        for (int i = 0; i < 2; ++i) {
            const int rc = mbedtls_ssl_close_notify(&ssl_);
            if (rc == 0) break;
            if (rc != MBEDTLS_ERR_SSL_WANT_READ &&
                rc != MBEDTLS_ERR_SSL_WANT_WRITE)
                break;
        }
    }

    const char* version() const { return mbedtls_ssl_get_version(&ssl_); }
    bool alpn_is_lgx2() const
    {
        const char* selected = mbedtls_ssl_get_alpn_protocol(&ssl_);
        return selected != nullptr && std::strcmp(selected, "lgx/2") == 0;
    }
    std::uint32_t verify_result() const
    {
        return mbedtls_ssl_get_verify_result(&ssl_);
    }
    std::string peer_subject() const
    {
        const mbedtls_x509_crt* peer = mbedtls_ssl_get_peer_cert(&ssl_);
        if (peer == nullptr) return {};
        char subject[512]{};
        const int rc = mbedtls_x509_dn_gets(subject, sizeof(subject),
                                            &peer->subject);
        return rc > 0 ? std::string(subject) : std::string();
    }

private:
    TlsSession(const TlsSession&);
    TlsSession& operator=(const TlsSession&);

    static int socket_send(void* ctx, const unsigned char* buf, std::size_t len)
    {
        const TlsNativeSocket s = *static_cast<TlsNativeSocket*>(ctx);
        for (;;) {
#ifdef _WIN32
            const int n = ::send(s, reinterpret_cast<const char*>(buf),
                                 static_cast<int>(len), 0);
            if (n >= 0) return n;
            const int socket_error = ::WSAGetLastError();
            if (socket_error == WSAEINTR) continue;
            if (socket_error == WSAEWOULDBLOCK || socket_error == WSAETIMEDOUT)
                return MBEDTLS_ERR_SSL_WANT_WRITE;
#else
            const int n = static_cast<int>(::send(s, buf, len,
#ifdef MSG_NOSIGNAL
                                                  MSG_NOSIGNAL
#else
                                                  0
#endif
            ));
            if (n >= 0) return n;
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return MBEDTLS_ERR_SSL_WANT_WRITE;
#endif
            return MBEDTLS_ERR_NET_SEND_FAILED;
        }
    }

    static int socket_recv(void* ctx, unsigned char* buf, std::size_t len)
    {
        const TlsNativeSocket s = *static_cast<TlsNativeSocket*>(ctx);
        for (;;) {
#ifdef _WIN32
            const int n = ::recv(s, reinterpret_cast<char*>(buf),
                                 static_cast<int>(len), 0);
            if (n >= 0) return n;
            const int socket_error = ::WSAGetLastError();
            if (socket_error == WSAEINTR) continue;
            if (socket_error == WSAEWOULDBLOCK || socket_error == WSAETIMEDOUT)
                return MBEDTLS_ERR_SSL_WANT_READ;
#else
            const int n = static_cast<int>(::recv(s, buf, len, 0));
            if (n >= 0) return n;
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return MBEDTLS_ERR_SSL_WANT_READ;
#endif
            return MBEDTLS_ERR_NET_RECV_FAILED;
        }
    }

    static bool fail(const char* where, int rc, std::string& error)
    {
        error = std::string(where) + ": " + tls_error_text(rc);
        return false;
    }

    mbedtls_ssl_context ssl_{};
    TlsNativeSocket socket_{};
};

} // namespace lgx
