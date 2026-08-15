// main.cpp - headless CLI client (used for automated end-to-end testing on
// Linux; shares the exact same worker-thread transfer engine as the GUI).
#include "../core/transfer.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

int main(int argc, char** argv)
{
    if (argc < 4) {
        std::printf("usage: log_client_cli <host> <port> <logfile> [result_out]\n");
        return 2;
    }
    const std::string host = argv[1];
    const int port = std::atoi(argv[2]);
    const std::filesystem::path log_path = argv[3];
    const std::filesystem::path out_path =
        argc >= 5 ? std::filesystem::path(argv[4])
                  : std::filesystem::path("result.csv");
    if (port <= 0 || port > 65535) {
        std::fprintf(stderr, "invalid port\n");
        return 2;
    }

    lgx::Progress prog;
    std::atomic<bool> cancel{false};

    // Same architecture as the GUI: transfer runs on a worker thread while
    // the "UI" (here: the console) keeps refreshing independently.
    std::thread worker([&] {
        lgx::run_transfer(host, static_cast<std::uint16_t>(port),
                          log_path, out_path, prog, cancel);
    });

    const char* stage_names[] = {"idle", "connecting", "uploading",
                                 "waiting-result", "downloading",
                                 "done", "failed", "cancelled"};
    for (;;) {
        const lgx::Stage st = prog.get_stage();
        const std::uint64_t sent = prog.sent.load();
        const std::uint64_t stot = prog.send_total.load();
        const std::uint64_t rcv  = prog.received.load();
        const std::uint64_t rtot = prog.recv_total.load();
        const double up = stot ? 100.0 * static_cast<double>(sent) /
                                 static_cast<double>(stot) : 0.0;
        const double dn = rtot ? 100.0 * static_cast<double>(rcv) /
                                 static_cast<double>(rtot) : 0.0;
        std::printf("\r[%-14s] upload %6.2f%% (%llu/%llu)  download %6.2f%%   ",
                    stage_names[static_cast<int>(st)], up,
                    (unsigned long long)sent, (unsigned long long)stot, dn);
        std::fflush(stdout);
        if (st == lgx::Stage::Done || st == lgx::Stage::Failed ||
            st == lgx::Stage::Cancelled)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    worker.join();
    std::printf("\n");

    if (prog.get_stage() == lgx::Stage::Done) {
        std::printf("OK: result saved to %s\n", out_path.string().c_str());
        return 0;
    }
    std::printf("FAILED: %s\n", prog.error().c_str());
    return 1;
}
