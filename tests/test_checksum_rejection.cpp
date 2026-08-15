// Integration helper: mutate a byte after the hashing pass reaches it.
#include "../client/core/transfer.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

int main(int argc, char** argv)
{
    if (argc != 9) return 2;
    const std::filesystem::path source = argv[3];
    const std::filesystem::path result = argv[4];
    lgx::Progress progress;
    std::atomic<bool> cancel{false};
    bool succeeded = true;
    std::thread worker([&] {
        succeeded = lgx::run_transfer(
            argv[1], static_cast<std::uint16_t>(std::stoi(argv[2])),
            source, result, progress, cancel, argv[5], argv[8], argv[6], argv[7]);
    });

    for (int i = 0; i < 10000; ++i) {
        if (progress.hashed.load() > 2 * 1024 * 1024) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    {
        std::fstream file(source, std::ios::binary | std::ios::in | std::ios::out);
        char byte = 0;
        file.read(&byte, 1);
        byte ^= 0x5A;
        file.seekp(0);
        file.write(&byte, 1);
        file.flush();
    }
    worker.join();

    if (succeeded || std::filesystem::exists(result) ||
        std::filesystem::exists(result.string() + ".lgxresume"))
        return 1;
    return progress.error().find("SHA-256 mismatch") != std::string::npos ? 0 : 1;
}
