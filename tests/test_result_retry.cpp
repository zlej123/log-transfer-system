// Integration helper for lost-result retry and atomic destination safety.
// Deadlines are wall-clock based so sanitizer builds on slow runners behave
// the same as release builds.
#include "../client/core/transfer.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

namespace {

using Clock = std::chrono::steady_clock;
constexpr auto kPhaseDeadline = std::chrono::seconds(600);

bool deadline_passed(Clock::time_point started)
{
    return Clock::now() - started > kPhaseDeadline;
}

int fail(const char* reason, const std::string& detail = {})
{
    std::fprintf(stderr, "test_result_retry: %s%s%s\n", reason,
                 detail.empty() ? "" : " | ", detail.c_str());
    return 1;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 9) return 2;
    const std::string host = argv[1];
    const auto port = static_cast<std::uint16_t>(std::stoi(argv[2]));
    const std::filesystem::path source = argv[3];
    const std::filesystem::path result = argv[4];
    const std::filesystem::path ca = argv[5], cert = argv[6], key = argv[7];
    const std::string server_name = argv[8];
    const std::filesystem::path sidecar = result.string() + ".lgxresume";

    const std::string prior = "prior-valid-result";
    { std::ofstream out(result, std::ios::binary | std::ios::trunc); out << prior; }

    // Phase 1: drop the connection after the upload is fully accepted but
    // before the result is delivered.
    lgx::Progress progress;
    std::atomic<bool> cancel{false};
    bool first_success = true;
    std::thread first([&] {
        first_success = lgx::run_transfer(host, port, source, result, progress,
                                          cancel, ca, server_name, cert, key);
    });
    bool reached_wait = false;
    const auto phase1 = Clock::now();
    while (!deadline_passed(phase1)) {
        const auto stage = progress.get_stage();
        if (stage == lgx::Stage::WaitingResult) {
            reached_wait = true;
            cancel.store(true);
            break;
        }
        if (stage == lgx::Stage::Done || stage == lgx::Stage::Failed) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    first.join();

    if (!reached_wait)
        return fail("never observed WaitingResult", progress.error());
    if (first_success) return fail("cancelled transfer reported success");
    if (!std::filesystem::exists(sidecar)) return fail("resume sidecar was lost");
    {
        std::ifstream in(result, std::ios::binary);
        const std::string kept((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
        if (kept != prior) return fail("prior result was clobbered", kept);
    }
    std::filesystem::copy_file(sidecar, result.string() + ".cachedtoken",
                               std::filesystem::copy_options::overwrite_existing);

    // Phase 2: the server keeps verifying and parsing after the client leaves,
    // so the same token is legitimately busy for a while. Retry until the
    // cached result is delivered.
    const std::uint64_t size = std::filesystem::file_size(source);
    const auto phase2 = Clock::now();
    std::string last_error;
    while (!deadline_passed(phase2)) {
        cancel.store(false);
        progress.reset();
        if (lgx::run_transfer(host, port, source, result, progress, cancel,
                              ca, server_name, cert, key)) {
            if (progress.resumed_offset.load() != size)
                return fail("retry did not resume at EOF");
            if (std::filesystem::exists(sidecar))
                return fail("sidecar survived a published result");
            return 0;
        }
        last_error = progress.error();
        if (last_error.find("upload currently active") == std::string::npos)
            return fail("retry failed for a non-busy reason", last_error);
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    return fail("retry never succeeded", last_error);
}
