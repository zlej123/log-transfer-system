// loggen.cpp - deterministic generator for the ~500 MB test log file.
//
// Produces lines like:
//   [2026-02-14 03:12:45.123] [INFO] [Engine] rpm=1740 temp=88.1 spd=63.42 ok
// and injects ~0.001% intentionally corrupted lines (missing brackets,
// binary garbage, truncated fields, bad numbers) to exercise the server's
// poison-data handling.
//
// STRICT RULE COMPLIANT: STL streams and containers own all resources.
#include <array>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <vector>

namespace {

constexpr std::array<const char*, 10> kModules = {
    "Engine", "Sensor", "GPS", "LiDAR", "Radar",
    "Battery", "Motor", "Comms", "Nav", "Diag"};
constexpr std::array<const char*, 4> kLevels = {"INFO", "WARN", "ERROR", "DEBUG"};

struct Clock {
    // starts 2026-02-14 00:00:00.000, advances 0-2 ms per line
    std::uint64_t ms = 0;
    int base_day = 14;
    void advance(std::uint64_t d) { ms += d; }
    void format(char* out, std::size_t cap) const
    {
        const std::uint64_t total_s = ms / 1000;
        const int msec = static_cast<int>(ms % 1000);
        const int sec  = static_cast<int>(total_s % 60);
        const int min  = static_cast<int>((total_s / 60) % 60);
        const std::uint64_t hours = total_s / 3600;
        const int hour = static_cast<int>(hours % 24);
        const int day  = base_day + static_cast<int>(hours / 24);
        std::snprintf(out, cap, "2026-02-%02d %02d:%02d:%02d.%03d",
                      day, hour, min, sec, msec);
    }
};

} // namespace

int main(int argc, char** argv)
{
    std::uint64_t target_bytes = 500ull * 1024 * 1024; // 500 MiB
    std::string out_path = "test_log_500mb.log";
    std::uint64_t seed = 20260214;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--size-mb" && i + 1 < argc)
            target_bytes = std::strtoull(argv[++i], nullptr, 10) * 1024ull * 1024ull;
        else if (a == "--out" && i + 1 < argc)
            out_path = argv[++i];
        else if (a == "--seed" && i + 1 < argc)
            seed = std::strtoull(argv[++i], nullptr, 10);
    }

    std::mt19937_64 rng(seed);
    std::uniform_int_distribution<int> mod_pick(0, kModules.size() - 1);
    std::uniform_int_distribution<int> lvl_pick(0, kLevels.size() - 1);
    std::uniform_int_distribution<int> ms_step(0, 2);
    std::uniform_real_distribution<double> spd_dist(0.0, 180.0);
    std::uniform_int_distribution<int> pct(0, 99);
    std::uniform_int_distribution<int> poison_roll(0, 99999); // 1e-5 = 0.001%
    std::uniform_int_distribution<int> poison_kind(0, 5);
    std::uniform_int_distribution<int> rpm_dist(600, 6000);
    std::uniform_real_distribution<double> temp_dist(20.0, 110.0);

    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        std::fprintf(stderr, "cannot open %s\n", out_path.c_str());
        return 1;
    }

    Clock clk;
    std::string buf;
    buf.reserve(4 * 1024 * 1024);
    std::uint64_t written = 0, lines = 0, poison = 0, spd_lines = 0;
    char ts[48], line[512];

    while (written + buf.size() < target_bytes) {
        clk.advance(static_cast<std::uint64_t>(ms_step(rng)));
        clk.format(ts, sizeof(ts));
        const char* mod = kModules[static_cast<std::size_t>(mod_pick(rng))];
        const char* lvl = kLevels[static_cast<std::size_t>(lvl_pick(rng))];

        int n = 0;
        const bool with_spd = pct(rng) < 30; // ~30% of lines carry a speed
        double spd = 0.0;
        if (with_spd) spd = spd_dist(rng);

        if (poison_roll(rng) == 0) {
            // ---- intentionally corrupted line (~0.001%) --------------------
            ++poison;
            switch (poison_kind(rng)) {
            case 0: // missing opening bracket
                n = std::snprintf(line, sizeof(line),
                    "%s] [%s] [%s] event=start spd=%.2f\n", ts, lvl, mod, spd);
                break;
            case 1: // missing closing bracket on module
                n = std::snprintf(line, sizeof(line),
                    "[%s] [%s] [%s event=heartbeat seq=%" PRIu64 "\n",
                    ts, lvl, mod, lines);
                break;
            case 2: // binary garbage in the middle
                n = std::snprintf(line, sizeof(line),
                    "[%s] [%s] [\x01\xFE\x7F\x02] \xDE\xAD\xBE\xEF corrupted\n",
                    ts, lvl);
                break;
            case 3: // truncated timestamp
                n = std::snprintf(line, sizeof(line),
                    "[2026-02-1 %s] [%s] event=stop\n", lvl, mod);
                break;
            case 4: // unparsable speed value
                n = std::snprintf(line, sizeof(line),
                    "[%s] [%s] [%s] velocity check spd=NaN?? unit=kmh\n",
                    ts, lvl, mod);
                break;
            default: // completely different format
                n = std::snprintf(line, sizeof(line),
                    "{\"ts\":\"%s\",\"mod\":\"%s\",\"spd\":oops}\n", ts, mod);
                break;
            }
        } else if (with_spd) {
            n = std::snprintf(line, sizeof(line),
                "[%s] [%s] [%s] rpm=%d temp=%.1f spd=%.2f status=ok\n",
                ts, lvl, mod, rpm_dist(rng), temp_dist(rng), spd);
            ++spd_lines;
        } else {
            n = std::snprintf(line, sizeof(line),
                "[%s] [%s] [%s] event=telemetry rpm=%d temp=%.1f status=ok\n",
                ts, lvl, mod, rpm_dist(rng), temp_dist(rng));
        }
        buf.append(line, static_cast<std::size_t>(n));
        ++lines;

        if (buf.size() >= 4 * 1024 * 1024 - 512) {
            out.write(buf.data(), static_cast<std::streamsize>(buf.size()));
            written += buf.size();
            buf.clear();
        }
    }
    out.write(buf.data(), static_cast<std::streamsize>(buf.size()));
    written += buf.size();

    std::printf("generated %s: %" PRIu64 " bytes, %" PRIu64 " lines, "
                "%" PRIu64 " poison lines (%.5f%%), %" PRIu64 " spd lines\n",
                out_path.c_str(), written, lines, poison,
                lines ? 100.0 * static_cast<double>(poison) /
                        static_cast<double>(lines) : 0.0,
                spd_lines);
    return 0;
}
