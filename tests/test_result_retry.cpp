// Integration helper for lost-result retry and atomic destination safety.
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
    {
        std::ofstream prior(result, std::ios::binary | std::ios::trunc);
        prior << "prior-valid-result";
    }

    lgx::Progress progress;
    std::atomic<bool> cancel{false};
    bool first_success = true;
    std::thread first([&] {
        first_success = lgx::run_transfer(
            argv[1], static_cast<std::uint16_t>(std::stoi(argv[2])),
            source, result, progress, cancel, argv[5], argv[8], argv[6], argv[7]);
    });
    bool reached_wait = false;
    for (int i = 0; i < 30000; ++i) {
        if (progress.get_stage() == lgx::Stage::WaitingResult) {
            reached_wait = true;
            cancel.store(true);
            break;
        }
        if (progress.get_stage() == lgx::Stage::Done ||
            progress.get_stage() == lgx::Stage::Failed)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    first.join();
    if (!reached_wait || first_success ||
        !std::filesystem::exists(result.string() + ".lgxresume"))
        return 1;
    {
        std::ifstream prior(result, std::ios::binary);
        std::string data((std::istreambuf_iterator<char>(prior)),
                         std::istreambuf_iterator<char>());
        if (data != "prior-valid-result") return 1;
    }

    std::filesystem::copy_file(
        result.string() + ".lgxresume", result.string() + ".cachedtoken",
        std::filesystem::copy_options::overwrite_existing);
    cancel.store(false);
    progress.reset();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    const bool second_success = lgx::run_transfer(
        argv[1], static_cast<std::uint16_t>(std::stoi(argv[2])),
        source, result, progress, cancel, argv[5], argv[8], argv[6], argv[7]);
    const std::uint64_t size = std::filesystem::file_size(source);
    return second_success && progress.resumed_offset.load() == size &&
           !std::filesystem::exists(result.string() + ".lgxresume") ? 0 : 1;
}
