// Persistent-store transaction, cache digest and recovery tests.
#include "../server/upload_store.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

int main()
{
    const auto root = std::filesystem::path("/tmp") /
        ("lgx-store-test-" + std::to_string(static_cast<long long>(::getpid())));
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    ::chmod(root.c_str(), 0700);

    lgx::Sha256 digest_builder;
    lgx::Sha256Digest digest{};
    const std::string source = "0123456789";
    if (!digest_builder.update(source.data(), source.size()) ||
        !digest_builder.finish(digest)) return 1;
    lgx::ResumeToken empty{};
    lgx::ResumeToken token{};
    std::string error;

    {
        lgx::UploadStore store(root, 1024 * 1024, 10,
                               std::chrono::hours(24));
        auto lease = store.begin(digest, empty, source.size(), "x.log",
                                 "CN=test", error);
        if (!lease) return 1;
        token = lease->record().token;
        {
            std::ofstream part(lease->record().part_path, std::ios::binary);
            part.write(source.data(), static_cast<std::streamsize>(source.size()));
        }
        if (!store.checkpoint(lease->record(), source.size(), error) ||
            !store.mark_complete(lease->record(), "verified-result", error) ||
            store.read_result(lease->record(), error) != "verified-result")
            return 1;
        lease.reset();

        auto completed = store.begin(digest, token, source.size(), "x.log",
                                     "CN=test", error);
        if (!completed || !completed->record().complete ||
            completed->record().offset != source.size() ||
            store.read_result(completed->record(), error) != "verified-result")
            return 1;
        {
            std::ofstream corrupt(completed->record().result_path,
                                  std::ios::binary | std::ios::trunc);
            corrupt << "changed";
        }
        error.clear();
        if (!store.read_result(completed->record(), error).empty() ||
            error.find("SHA-256 mismatch") == std::string::npos)
            return 1;
        std::filesystem::remove(completed->record().result_path);
        completed.reset();
        error.clear();
        auto missing_cache = store.begin(digest, token, source.size(), "x.log",
                                         "CN=test", error);
        if (missing_cache || error.find("cache is missing") == std::string::npos)
            return 1;
    }

    // A physical tail beyond the committed manifest offset is never trusted.
    lgx::Sha256Digest second_digest{};
    lgx::Sha256 second_hash;
    second_hash.update("abcde", 5);
    second_hash.finish(second_digest);
    lgx::ResumeToken second_token{};
    {
        lgx::UploadStore store(root, 1024 * 1024, 10,
                               std::chrono::hours(24));
        auto lease = store.begin(second_digest, empty, 5, "tail.log",
                                 "CN=test", error);
        if (!lease) return 1;
        second_token = lease->record().token;
        {
            std::ofstream part(lease->record().part_path, std::ios::binary);
            part << "abcdeTAIL";
        }
        if (!store.checkpoint(lease->record(), 5, error)) return 1;
    }
    {
        lgx::UploadStore store(root, 1024 * 1024, 10,
                               std::chrono::hours(24));
        auto recovered = store.begin(second_digest, second_token, 5, "tail.log",
                                     "CN=test", error);
        if (!recovered ||
            std::filesystem::file_size(recovered->record().part_path) != 5)
            return 1;
        const auto recovered_part = recovered->record().part_path;
        recovered.reset();
        std::filesystem::resize_file(recovered_part, 4);
        error.clear();
        auto too_short = store.begin(second_digest, second_token, 5, "tail.log",
                                     "CN=test", error);
        if (too_short || error.find("shorter") == std::string::npos) return 1;
    }

    // A crash-left durable staging artifact is never treated as a manifest.
    const auto stale_stage = root /
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.meta.tmp";
    { std::ofstream stage(stale_stage); stage << "incomplete"; }
    {
        lgx::UploadStore store(root, 1024 * 1024, 10,
                               std::chrono::hours(24));
        if (std::filesystem::exists(stale_stage)) return 1;
    }

    std::filesystem::remove_all(root);

    const auto ttl_root = std::filesystem::path("/tmp") /
        ("lgx-store-ttl-test-" +
         std::to_string(static_cast<long long>(::getpid())));
    std::filesystem::create_directories(ttl_root);
    ::chmod(ttl_root.c_str(), 0700);
    {
        lgx::UploadStore store(ttl_root, 1024 * 1024, 10,
                               std::chrono::hours(0));
        auto expired = store.begin(second_digest, empty, 5, "expired.log",
                                   "CN=test", error);
        if (!expired) return 1;
        const auto expired_token = expired->record().token;
        expired.reset();
        ::usleep(2000);
        auto trigger = store.begin(second_digest, empty, 5, "trigger.log",
                                   "CN=test", error);
        if (!trigger) return 1;
        trigger.reset();
        error.clear();
        auto should_be_gone = store.begin(second_digest, expired_token, 5,
                                          "expired.log", "CN=test", error);
        if (should_be_gone ||
            error.find("unknown or expired") == std::string::npos)
            return 1;
    }
    std::filesystem::remove_all(ttl_root);

    const auto deletion_root = std::filesystem::path("/tmp") /
        ("lgx-store-retention-test-" +
         std::to_string(static_cast<long long>(::getpid())));
    std::filesystem::create_directories(deletion_root);
    ::chmod(deletion_root.c_str(), 0700);
    {
        lgx::UploadStore store(deletion_root, 10, 10,
                               std::chrono::hours(24));
        auto retained = store.begin(second_digest, empty, 10, "retained.log",
                                    "CN=test", error);
        if (!retained) return 1;
        {
            std::ofstream part(retained->record().part_path, std::ios::binary);
            part << "0123456789";
        }
        ::chmod(deletion_root.c_str(), 0500);
        if (store.discard(retained->record())) return 1;
        retained.reset();
        ::chmod(deletion_root.c_str(), 0700);
        error.clear();
        if (store.begin(second_digest, empty, 1, "blocked.log",
                        "CN=test", error) ||
            error.find("quota exceeded") == std::string::npos)
            return 1;
    }
    std::filesystem::remove_all(deletion_root);

    const auto orphan_root = std::filesystem::path("/tmp") /
        ("lgx-store-orphan-test-" +
         std::to_string(static_cast<long long>(::getpid())));
    std::filesystem::create_directories(orphan_root);
    ::chmod(orphan_root.c_str(), 0700);
    {
        std::ofstream orphan(orphan_root /
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.part",
            std::ios::binary);
        orphan << "0123456789";
    }
    {
        lgx::UploadStore store(orphan_root, 10, 10,
                               std::chrono::hours(24));
        error.clear();
        if (store.begin(second_digest, empty, 1, "blocked.log",
                        "CN=test", error) ||
            error.find("quota exceeded") == std::string::npos)
            return 1;
    }
    std::filesystem::remove_all(orphan_root);

    const auto corrupt_root = std::filesystem::path("/tmp") /
        ("lgx-store-corrupt-test-" +
         std::to_string(static_cast<long long>(::getpid())));
    std::filesystem::create_directories(corrupt_root);
    ::chmod(corrupt_root.c_str(), 0700);
    const std::string corrupt_id(64, 'c');
    { std::ofstream meta(corrupt_root / (corrupt_id + ".meta")); meta << "bad"; }
    { std::ofstream part(corrupt_root / (corrupt_id + ".part"),
                         std::ios::binary); part << "0123456789"; }
    {
        lgx::UploadStore store(corrupt_root, 10, 10,
                               std::chrono::hours(24));
        error.clear();
        if (store.begin(second_digest, empty, 1, "blocked.log",
                        "CN=test", error) ||
            error.find("quota exceeded") == std::string::npos)
            return 1;
    }
    std::filesystem::remove_all(corrupt_root);
    return 0;
}
