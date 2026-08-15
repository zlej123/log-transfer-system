// Persistent resumable-upload store with durable offsets and bounded quotas.
#pragma once

#include "../common/hash.hpp"
#include "../common/protocol.hpp"
#include "file_io.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace lgx {

using ResumeToken = std::array<unsigned char, kResumeTokenSize>;

struct UploadRecord {
    ResumeToken token{};
    Sha256Digest digest{};
    Sha256Digest result_digest{};
    std::uint64_t total_size = 0;
    std::uint64_t offset = 0; // last durable checkpoint
    std::string name;
    std::string principal;
    bool complete = false;
    std::filesystem::path part_path;
    std::filesystem::path result_path;
    std::filesystem::path meta_path;
};

class UploadLease {
public:
    UploadLease(UploadRecord record, std::unique_lock<std::mutex> lock)
        : record_(std::move(record)), lock_(std::move(lock)) {}
    UploadLease(UploadLease&&) = default;
    UploadLease& operator=(UploadLease&&) = default;

    UploadRecord& record() { return record_; }
    const UploadRecord& record() const { return record_; }

private:
    UploadLease(const UploadLease&);
    UploadLease& operator=(const UploadLease&);
    UploadRecord record_;
    std::unique_lock<std::mutex> lock_;
};

class UploadStore {
public:
    UploadStore(std::filesystem::path root, std::uint64_t max_reserved_bytes,
                std::size_t max_partial_count, std::chrono::hours ttl)
        : root_(std::move(root)), max_reserved_bytes_(max_reserved_bytes),
          max_partial_count_(max_partial_count), ttl_(ttl)
    {
        std::error_code ec;
        std::filesystem::create_directories(root_, ec);
        ::chmod(root_.c_str(), 0700);
        cleanup_expired_and_orphans();
        rebuild_quota_state();
    }

    std::optional<UploadLease> begin(const Sha256Digest& digest,
                                     const ResumeToken& requested_token,
                                     std::uint64_t total_size,
                                     const std::string& name,
                                     const std::string& principal,
                                     std::string& error)
    {
        const bool initial = all_zero(requested_token);
        if (initial) cleanup_runtime_expired();
        ResumeToken token = requested_token;
        if (initial && !secure_token(token)) {
            error = "secure token generation failed";
            return std::nullopt;
        }

        std::unique_lock<std::mutex> upload_lock(
            stripes_[static_cast<std::size_t>(token[0]) % stripes_.size()],
            std::defer_lock);
        if (!upload_lock.try_lock()) {
            error = "upload currently active";
            return std::nullopt;
        }
        UploadRecord record = paths_for(token);

        if (initial) {
            std::lock_guard<std::mutex> quota_lock(quota_mutex_);
            if (partial_count_ >= max_partial_count_ ||
                record_count_ >= max_partial_count_ * 4 ||
                total_size > max_reserved_bytes_ -
                    std::min(reserved_bytes_, max_reserved_bytes_)) {
                error = "partial-upload quota exceeded";
                return std::nullopt;
            }
            if (std::filesystem::exists(record.meta_path)) {
                error = "token collision";
                return std::nullopt;
            }
            record.digest = digest;
            record.total_size = total_size;
            record.name = name;
            record.principal = principal;
            record.offset = 0;
            if (!write_record(record, error)) return std::nullopt;
            ++partial_count_;
            ++record_count_;
            reserved_bytes_ += total_size;
        } else {
            if (!read_record(record, error)) return std::nullopt;
            if (!digest_equal(record.digest, digest) ||
                record.total_size != total_size || record.name != name ||
                record.principal != principal) {
                error = "resume token metadata mismatch";
                return std::nullopt;
            }
        }

        if (record.complete) {
            std::error_code ec;
            if (!std::filesystem::exists(record.result_path, ec)) {
                error = "completed upload cache is missing";
                return std::nullopt;
            }
            record.offset = record.total_size;
        } else {
            std::error_code ec;
            const std::uint64_t physical =
                std::filesystem::exists(record.part_path, ec)
                    ? std::filesystem::file_size(record.part_path, ec) : 0;
            if (ec || physical < record.offset || record.offset > record.total_size) {
                error = "partial upload is shorter than its durable checkpoint";
                return std::nullopt;
            }
            if (physical > record.offset && !truncate_to_checkpoint(record, error))
                return std::nullopt;
        }

        // Refresh activity under the exclusive lease. The durable manifest is
        // also the authoritative committed offset after a restart.
        if (!write_record(record, error)) return std::nullopt;
        return UploadLease(std::move(record), std::move(upload_lock));
    }

    bool checkpoint(UploadRecord& record, std::uint64_t durable_offset,
                    std::string& error)
    {
        if (record.complete || durable_offset < record.offset ||
            durable_offset > record.total_size) {
            error = "invalid durable checkpoint";
            return false;
        }
        const std::uint64_t previous = record.offset;
        record.offset = durable_offset;
        if (!write_record(record, error)) {
            record.offset = previous;
            return false;
        }
        return true;
    }

    bool mark_complete(UploadRecord& record, const std::string& result,
                       std::string& error)
    {
        if (record.offset != record.total_size) {
            error = "upload is not durably complete";
            return false;
        }
        Sha256 result_hash;
        if (!result_hash.update(result.data(), result.size()) ||
            !result_hash.finish(record.result_digest)) {
            error = "result SHA-256 failed";
            return false;
        }
        if (!durable_replace(record.result_path, result, error)) return false;
        record.complete = true;
        if (!write_record(record, error)) {
            record.complete = false;
            return false;
        }

        std::error_code remove_error;
        const bool part_removed = !std::filesystem::exists(record.part_path) ||
                                  std::filesystem::remove(record.part_path,
                                                          remove_error);
        const bool directory_synced = part_removed && sync_directory(root_);
        {
            std::lock_guard<std::mutex> lock(quota_mutex_);
            if (partial_count_ > 0) --partial_count_;
            reserved_bytes_ = record.total_size <= reserved_bytes_
                ? reserved_bytes_ - record.total_size : 0;
            reserved_bytes_ += static_cast<std::uint64_t>(result.size());
            if (!part_removed || !directory_synced)
                reserved_bytes_ += record.total_size;
        }
        return true;
    }

    std::string read_result(const UploadRecord& record, std::string& error) const
    {
        std::error_code size_error;
        const auto size = std::filesystem::file_size(record.result_path, size_error);
        if (size_error || size > kMaxResultSize) {
            error = "result cache has invalid size";
            return {};
        }
        std::ifstream input(record.result_path, std::ios::binary);
        if (!input) { error = "cannot read result cache"; return {}; }
        std::string data((std::istreambuf_iterator<char>(input)),
                         std::istreambuf_iterator<char>());
        if (input.bad()) { error = "result cache read failed"; return {}; }
        Sha256 hash;
        Sha256Digest actual{};
        if (!hash.update(data.data(), data.size()) || !hash.finish(actual) ||
            !digest_equal(actual, record.result_digest)) {
            error = "result cache SHA-256 mismatch";
            return {};
        }
        return data;
    }

    bool discard(UploadRecord& record)
    {
        std::uint64_t charged = record.complete ? 0 : record.total_size;
        std::error_code size_error;
        if (record.complete) {
            if (std::filesystem::exists(record.result_path, size_error))
                charged += std::filesystem::file_size(record.result_path, size_error);
            if (std::filesystem::exists(record.part_path, size_error))
                charged += std::filesystem::file_size(record.part_path, size_error);
        }
        std::error_code ec_part, ec_result, ec_meta;
        const bool part_ok = !std::filesystem::exists(record.part_path) ||
                             std::filesystem::remove(record.part_path, ec_part);
        const bool result_ok = !std::filesystem::exists(record.result_path) ||
                               std::filesystem::remove(record.result_path,
                                                       ec_result);
        if (!part_ok || !result_ok || !sync_directory(root_)) return false;
        const bool meta_ok = !std::filesystem::exists(record.meta_path) ||
                             std::filesystem::remove(record.meta_path, ec_meta);
        if (!meta_ok || !sync_directory(root_)) return false;

        std::lock_guard<std::mutex> lock(quota_mutex_);
        if (!record.complete && partial_count_ > 0) --partial_count_;
        reserved_bytes_ = charged <= reserved_bytes_
            ? reserved_bytes_ - charged : 0;
        if (record_count_ > 0) --record_count_;
        return true;
    }

private:
    UploadStore(const UploadStore&);
    UploadStore& operator=(const UploadStore&);

    static bool all_zero(const ResumeToken& token)
    {
        unsigned int bits = 0;
        for (unsigned char value : token) bits |= value;
        return bits == 0;
    }

    static bool secure_token(ResumeToken& token)
    {
        std::ifstream random("/dev/urandom", std::ios::binary);
        if (!random) return false;
        random.read(reinterpret_cast<char*>(token.data()),
                    static_cast<std::streamsize>(token.size()));
        return static_cast<bool>(random) && !all_zero(token);
    }

    UploadRecord paths_for(const ResumeToken& token) const
    {
        UploadRecord record;
        record.token = token;
        const std::string id = hex_encode(token.data(), token.size());
        record.part_path = root_ / (id + ".part");
        record.result_path = root_ / (id + ".csv");
        record.meta_path = root_ / (id + ".meta");
        return record;
    }

    bool write_record(const UploadRecord& record, std::string& error) const
    {
        std::ostringstream text;
        text << "LGX_UPLOAD_V3\n"
             << "token=" << hex_encode(record.token.data(), record.token.size()) << '\n'
             << "digest=" << hex_encode(record.digest.data(), record.digest.size()) << '\n'
             << "result_digest=" << hex_encode(record.result_digest.data(), record.result_digest.size()) << '\n'
             << "size=" << record.total_size << '\n'
             << "offset=" << record.offset << '\n'
             << "state=" << (record.complete ? "complete" : "partial") << '\n'
             << "name=" << record.name << '\n'
             << "principal=" << record.principal << '\n';
        return durable_replace(record.meta_path, text.str(), error);
    }

    bool read_record(UploadRecord& record, std::string& error) const
    {
        std::error_code size_error;
        if (!std::filesystem::exists(record.meta_path, size_error) || size_error) {
            error = "unknown or expired resume token";
            return false;
        }
        const auto metadata_size = std::filesystem::file_size(record.meta_path,
                                                               size_error);
        if (size_error || metadata_size > 8192) {
            error = "invalid upload metadata size";
            return false;
        }
        std::ifstream input(record.meta_path);
        if (!input) { error = "unknown or expired resume token"; return false; }
        std::string line;
        if (!std::getline(input, line) || line != "LGX_UPLOAD_V3") {
            error = "invalid upload metadata version";
            return false;
        }
        std::string token_hex, digest_hex, result_digest_hex, size_text, offset_text;
        std::string state, name, principal;
        while (std::getline(input, line)) {
            const auto split = line.find('=');
            if (split == std::string::npos) continue;
            const auto key = line.substr(0, split);
            const auto value = line.substr(split + 1);
            if (key == "token") token_hex = value;
            else if (key == "digest") digest_hex = value;
            else if (key == "result_digest") result_digest_hex = value;
            else if (key == "size") size_text = value;
            else if (key == "offset") offset_text = value;
            else if (key == "state") state = value;
            else if (key == "name") name = value;
            else if (key == "principal") principal = value;
        }
        ResumeToken token{};
        Sha256Digest digest{};
        Sha256Digest result_digest{};
        if (!hex_decode(token_hex, token.data(), token.size()) ||
            !hex_decode(digest_hex, digest.data(), digest.size()) ||
            !hex_decode(result_digest_hex, result_digest.data(), result_digest.size()) ||
            token != record.token || name.empty() || principal.empty() ||
            (state != "partial" && state != "complete")) {
            error = "corrupt upload metadata";
            return false;
        }
        std::uint64_t total = 0, offset = 0;
        if (!parse_uint64(size_text, total) || !parse_uint64(offset_text, offset) ||
            total > kMaxPayloadSize || offset > total) {
            error = "corrupt upload size/offset metadata";
            return false;
        }
        record.digest = digest;
        record.result_digest = result_digest;
        record.total_size = total;
        record.offset = offset;
        record.name = name;
        record.principal = principal;
        record.complete = (state == "complete");
        if (record.complete && record.offset != record.total_size) {
            error = "corrupt completed upload metadata";
            return false;
        }
        return true;
    }

    static bool parse_uint64(const std::string& text, std::uint64_t& value)
    {
        try {
            std::size_t consumed = 0;
            value = std::stoull(text, &consumed);
            return consumed == text.size();
        } catch (...) {
            return false;
        }
    }

    bool truncate_to_checkpoint(const UploadRecord& record,
                                std::string& error) const
    {
        FileHandle part(::open(record.part_path.c_str(),
            O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
        if (!part.valid() ||
            ::ftruncate(part.get(), static_cast<off_t>(record.offset)) != 0 ||
            !part.sync_all() || !sync_directory(root_)) {
            error = "cannot recover uncommitted upload tail";
            return false;
        }
        return true;
    }

    void cleanup_runtime_expired()
    {
        std::unique_lock<std::mutex> maintenance(maintenance_mutex_,
                                                 std::try_to_lock);
        if (!maintenance.owns_lock()) return;
        std::error_code ec;
        const auto now = std::filesystem::file_time_type::clock::now();
        for (const auto& entry : std::filesystem::directory_iterator(root_, ec)) {
            if (ec || entry.path().extension() != ".meta") continue;
            ResumeToken token{};
            if (!hex_decode(entry.path().stem().string(), token.data(), token.size()))
                continue;
            std::unique_lock<std::mutex> upload_lock(
                stripes_[static_cast<std::size_t>(token[0]) % stripes_.size()],
                std::try_to_lock);
            if (!upload_lock.owns_lock()) continue;
            const auto changed = entry.last_write_time(ec);
            if (ec || now - changed <= ttl_) continue;
            UploadRecord record = paths_for(token);
            std::string ignored;
            if (read_record(record, ignored)) discard(record);
        }
    }

    void cleanup_expired_and_orphans()
    {
        std::error_code ec;
        const auto now = std::filesystem::file_time_type::clock::now();
        for (const auto& entry : std::filesystem::directory_iterator(root_, ec)) {
            if (ec) break;
            const auto extension = entry.path().extension();
            if (extension == ".tmp") {
                std::filesystem::remove(entry.path(), ec);
                continue;
            }
            const auto changed = entry.last_write_time(ec);
            if (ec || now - changed <= ttl_) continue;

            if (extension == ".meta") {
                const auto stem = entry.path().stem().string();
                std::error_code part_error, result_error, meta_error;
                const auto part = root_ / (stem + ".part");
                const auto result = root_ / (stem + ".csv");
                const bool part_ok = !std::filesystem::exists(part) ||
                                     std::filesystem::remove(part, part_error);
                const bool result_ok = !std::filesystem::exists(result) ||
                                       std::filesystem::remove(result,
                                                               result_error);
                if (part_ok && result_ok)
                    std::filesystem::remove(entry.path(), meta_error);
            } else if (extension == ".part" || extension == ".csv") {
                const auto meta = root_ / (entry.path().stem().string() + ".meta");
                if (!std::filesystem::exists(meta))
                    std::filesystem::remove(entry.path(), ec);
            }
        }
        sync_directory(root_);
    }

    void rebuild_quota_state()
    {
        reserved_bytes_ = 0;
        partial_count_ = 0;
        record_count_ = 0;
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator(root_, ec)) {
            if (ec || entry.path().extension() != ".meta") continue;
            ResumeToken token{};
            const std::string id = entry.path().stem().string();
            if (!hex_decode(id, token.data(), token.size())) continue;
            UploadRecord record = paths_for(token);
            ++record_count_;
            std::string ignored;
            if (!read_record(record, ignored)) {
                std::error_code physical_error;
                if (std::filesystem::exists(record.part_path, physical_error))
                    reserved_bytes_ +=
                        std::filesystem::file_size(record.part_path, physical_error);
                if (std::filesystem::exists(record.result_path, physical_error))
                    reserved_bytes_ +=
                        std::filesystem::file_size(record.result_path, physical_error);
                continue;
            }
            if (!record.complete) {
                ++partial_count_;
                reserved_bytes_ += record.total_size;
            } else {
                std::error_code physical_error;
                if (std::filesystem::exists(record.result_path, physical_error))
                    reserved_bytes_ +=
                        std::filesystem::file_size(record.result_path, physical_error);
                if (std::filesystem::exists(record.part_path, physical_error))
                    reserved_bytes_ +=
                        std::filesystem::file_size(record.part_path, physical_error);
            }
        }
        // Any untracked retained part still consumes the global disk budget.
        for (const auto& entry : std::filesystem::directory_iterator(root_, ec)) {
            if (ec || (entry.path().extension() != ".part" &&
                       entry.path().extension() != ".csv")) continue;
            const auto meta = root_ / (entry.path().stem().string() + ".meta");
            if (!std::filesystem::exists(meta))
                reserved_bytes_ += entry.file_size(ec);
        }
    }

    std::filesystem::path root_;
    std::uint64_t max_reserved_bytes_;
    std::size_t max_partial_count_;
    std::chrono::hours ttl_;
    std::array<std::mutex, 64> stripes_{};
    std::mutex quota_mutex_;
    std::mutex maintenance_mutex_;
    std::uint64_t reserved_bytes_ = 0;
    std::size_t partial_count_ = 0;
    std::size_t record_count_ = 0;
};

} // namespace lgx
