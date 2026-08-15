// parser.hpp - incremental (streaming) log analyzer.
//
// The 500 MB log is NEVER held in memory: bytes are fed chunk-by-chunk as
// they arrive from the socket, and only bounded aggregates are kept.
//
// Expected well-formed line:
//   [YYYY-MM-DD HH:MM:SS.mmm] [LEVEL] [Module] message text ... spd=12.34 ...
//
// ~0.001% of lines are intentionally corrupted (missing brackets, garbage
// bytes, format mismatches). Every validation failure is contained: the
// line is counted, a sample is recorded, and parsing continues.
//
// STRICT RULE COMPLIANT: std::string/std::vector with bounded state only.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace lgx {

class LogAnalyzer {
public:
    // Hard bounds that keep memory usage constant even under hostile input.
    static constexpr std::size_t kMaxLineLen        = 64 * 1024; // 64 KiB per line
    static constexpr std::size_t kMaxBucketEntries  = 200000;    // module x hour
    static constexpr std::size_t kMaxErrorSamples   = 200;       // kept in RAM

    // Feed the next chunk of raw bytes from the stream.
    void feed(const char* data, std::size_t len);

    // Flush the trailing line (file may not end with '\n').
    void finish();

    // Render the final result.csv content.
    std::string make_csv() const;

    // Render a short human-readable summary (for server log).
    std::string summary() const;

    const std::vector<std::string>& error_samples() const { return error_samples_; }
    std::uint64_t total_lines() const { return total_lines_; }
    std::uint64_t valid_lines() const { return valid_lines_; }
    std::uint64_t malformed_lines() const { return malformed_lines_; }

private:
    void process_line(const char* s, std::size_t n);
    void mark_malformed(const char* s, std::size_t n, const char* reason);
    bool parse_speed(const char* msg, std::size_t n, double& out) const;

    // --- streaming state -----------------------------------------------
    std::string carry_;                 // partial line between chunks
    bool        discarding_ = false;    // inside an over-long (poison) line

    // --- Task 1: per-module per-hour event counts -----------------------
    // key = "<module>\x1F<YYYY-MM-DD HH>"  ->  count
    std::unordered_map<std::string, std::uint64_t> bucket_counts_;
    bool bucket_overflow_ = false;

    // --- Task 2: average speed over lines containing "spd" --------------
    long double   spd_sum_   = 0.0L;
    std::uint64_t spd_count_ = 0;
    double        spd_min_   = 0.0;
    double        spd_max_   = 0.0;

    // --- bookkeeping -----------------------------------------------------
    std::uint64_t total_lines_     = 0;
    std::uint64_t valid_lines_     = 0;
    std::uint64_t malformed_lines_ = 0;
    std::uint64_t bytes_seen_      = 0;
    std::vector<std::string> error_samples_;
};

} // namespace lgx
