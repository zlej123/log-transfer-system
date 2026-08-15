// Checked POSIX file operations used by durable upload transactions.
#pragma once

#include <cerrno>
#include <cstddef>
#include <filesystem>
#include <string>
#include <utility>

#include <fcntl.h>
#include <unistd.h>

namespace lgx {

class FileHandle {
public:
    FileHandle() = default;
    explicit FileHandle(int value) : value_(value) {}
    ~FileHandle() { reset(); }
    FileHandle(FileHandle&& other) noexcept : value_(other.value_)
    {
        other.value_ = -1;
    }
    FileHandle& operator=(FileHandle&& other) noexcept
    {
        if (this != &other) {
            reset();
            value_ = other.value_;
            other.value_ = -1;
        }
        return *this;
    }

    bool valid() const { return value_ >= 0; }
    int get() const { return value_; }
    void reset()
    {
        if (value_ >= 0) { ::close(value_); value_ = -1; }
    }

    bool write_all(const void* data, std::size_t size)
    {
        const char* current = static_cast<const char*>(data);
        std::size_t remaining = size;
        while (remaining > 0) {
            const ssize_t count = ::write(value_, current, remaining);
            if (count > 0) {
                current += count;
                remaining -= static_cast<std::size_t>(count);
                continue;
            }
            if (count < 0 && errno == EINTR) continue;
            return false;
        }
        return true;
    }

    bool sync_data() { return value_ >= 0 && ::fdatasync(value_) == 0; }
    bool sync_all() { return value_ >= 0 && ::fsync(value_) == 0; }

private:
    FileHandle(const FileHandle&);
    FileHandle& operator=(const FileHandle&);
    int value_ = -1;
};

inline bool sync_directory(const std::filesystem::path& path)
{
    FileHandle directory(::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    return directory.valid() && directory.sync_all();
}

inline bool durable_replace(const std::filesystem::path& destination,
                            const std::string& content, std::string& error)
{
    const auto staging = std::filesystem::path(destination.string() + ".tmp");
    FileHandle output(::open(staging.c_str(),
        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (!output.valid() || !output.write_all(content.data(), content.size()) ||
        !output.sync_all()) {
        error = "durable staging write failed";
        return false;
    }
    output.reset();
    if (::rename(staging.c_str(), destination.c_str()) != 0 ||
        !sync_directory(destination.parent_path())) {
        error = "durable publish failed";
        return false;
    }
    return true;
}

} // namespace lgx
