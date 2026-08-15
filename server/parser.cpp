// parser.cpp - implementation of the streaming log analyzer.
#include "parser.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <map>

namespace lgx {
namespace {

inline bool is_digit(char c) { return c >= '0' && c <= '9'; }

inline int two_digits(const char* p) { return (p[0] - '0') * 10 + (p[1] - '0'); }
inline int four_digits(const char* p)
{
    return (p[0] - '0') * 1000 + (p[1] - '0') * 100 +
           (p[2] - '0') * 10 + (p[3] - '0');
}

// Strict timestamp check: "[YYYY-MM-DD HH:MM:SS.mmm]" at s[0..24].
// Returns true and fills `hour_key` with "YYYY-MM-DD HH" on success.
bool check_timestamp(const char* s, std::size_t n, std::string& hour_key)
{
    if (n < 25 || s[0] != '[') return false;
    static constexpr std::array<std::size_t, 17> digit_pos =
        {1,2,3,4, 6,7, 9,10, 12,13, 15,16, 18,19, 21,22,23};
    for (std::size_t pos : digit_pos)
        if (!is_digit(s[pos])) return false;
    if (s[5] != '-' || s[8] != '-' || s[11] != ' ' ||
        s[14] != ':' || s[17] != ':' || s[20] != '.' || s[24] != ']')
        return false;

    const int year  = four_digits(s + 1);
    const int month = two_digits(s + 6);
    const int day   = two_digits(s + 9);
    const int hour  = two_digits(s + 12);
    const int min   = two_digits(s + 15);
    const int sec   = two_digits(s + 18);
    static constexpr int kMonthDays[] =
        {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month < 1 || month > 12 || day < 1 ||
        hour > 23 || min > 59 || sec > 59)
        return false;
    int max_day = kMonthDays[month];
    const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    if (month == 2 && leap) ++max_day;
    if (day > max_day) return false;

    hour_key.assign(s + 1, 13); // "YYYY-MM-DD HH"
    return true;
}

// Parse a bracketed token "[TOKEN]" starting at s[off]. On success advances
// `off` past the closing bracket and fills `tok`.
bool take_bracket_token(const char* s, std::size_t n, std::size_t& off,
                        std::string& tok, std::size_t max_tok,
                        bool module_charset)
{
    if (off >= n || s[off] != '[') return false;
    const std::size_t start = off + 1;
    std::size_t end = start;
    while (end < n && s[end] != ']') {
        if (end - start >= max_tok) return false;
        ++end;
    }
    if (end >= n || end == start) return false; // no ']' or empty token
    for (std::size_t i = start; i < end; ++i) {
        const char c = s[i];
        const bool ok = module_charset
            ? (is_digit(c) || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               c == '_' || c == '-' || c == '.')
            : ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
        if (!ok) return false;
    }
    tok.assign(s + start, end - start);
    off = end + 1;
    return true;
}

std::string escape_sample(const char* s, std::size_t n)
{
    static constexpr std::size_t kMax = 120;
    std::string out;
    out.reserve(std::min(n, kMax) + 8);
    for (std::size_t i = 0; i < n && i < kMax; ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c >= 0x20 && c < 0x7F) {
            out.push_back(static_cast<char>(c));
        } else {
            char hex[8];
            std::snprintf(hex, sizeof(hex), "\\x%02X", c);
            out += hex;
        }
    }
    if (n > kMax) out += "...";
    return out;
}

std::string csv_escape(const std::string& v)
{
    if (v.find_first_of(",\"\r\n") == std::string::npos) return v;
    std::string out;
    out.reserve(v.size() + 8);
    out.push_back('"');
    for (char c : v) {
        if (c == '"') out += "\"\"";
        else out.push_back(c);
    }
    out.push_back('"');
    return out;
}

} // namespace

void LogAnalyzer::feed(const char* data, std::size_t len)
{
    bytes_seen_ += len;
    std::size_t i = 0;
    while (i < len) {
        // Poison guard: a "line" longer than kMaxLineLen is dropped without
        // ever being buffered, so hostile input cannot grow our memory.
        if (discarding_) {
            while (i < len && data[i] != '\n') ++i;
            if (i < len) { ++i; discarding_ = false; } // consumed the '\n'
            continue;
        }

        const char* nl = static_cast<const char*>(
            std::memchr(data + i, '\n', len - i));
        if (nl == nullptr) {
            // No newline in the rest of this chunk: stash and wait for more.
            if (carry_.size() + (len - i) > kMaxLineLen) {
                ++total_lines_; // this over-long line is consumed right here
                mark_malformed(carry_.data(),
                               std::min(carry_.size(), std::size_t(64)),
                               "line exceeds max length");
                carry_.clear();
                discarding_ = true;
                continue;
            }
            carry_.append(data + i, len - i);
            break;
        }

        const std::size_t line_end = static_cast<std::size_t>(nl - data);
        if (!carry_.empty()) {
            if (carry_.size() + (line_end - i) > kMaxLineLen) {
                ++total_lines_;
                mark_malformed(carry_.data(),
                               std::min(carry_.size(), std::size_t(64)),
                               "line exceeds max length");
            } else {
                carry_.append(data + i, line_end - i);
                process_line(carry_.data(), carry_.size());
            }
            carry_.clear();
        } else if (line_end - i > kMaxLineLen) {
            ++total_lines_;
            mark_malformed(data + i, std::min(line_end - i, std::size_t(64)),
                           "line exceeds max length");
        } else {
            process_line(data + i, line_end - i);
        }
        i = line_end + 1;
    }
}

void LogAnalyzer::finish()
{
    if (!carry_.empty()) {
        process_line(carry_.data(), carry_.size());
        carry_.clear();
    }
    discarding_ = false;
}

void LogAnalyzer::process_line(const char* s, std::size_t n)
{
    // Tolerate CRLF input.
    if (n > 0 && s[n - 1] == '\r') --n;
    ++total_lines_;
    if (n == 0) {
        mark_malformed(s, n, "blank line");
        return;
    }

    std::string hour_key;
    if (!check_timestamp(s, n, hour_key)) {
        mark_malformed(s, n, "bad timestamp / missing bracket");
        return;
    }

    std::size_t off = 25;
    if (off >= n || s[off] != ' ') {
        mark_malformed(s, n, "missing separator after timestamp");
        return;
    }
    ++off;

    std::string level;
    if (!take_bracket_token(s, n, off, level, 8, /*module_charset=*/false)) {
        mark_malformed(s, n, "bad level field");
        return;
    }
    if (off >= n || s[off] != ' ') {
        mark_malformed(s, n, "missing separator after level");
        return;
    }
    ++off;

    std::string module;
    if (!take_bracket_token(s, n, off, module, 64, /*module_charset=*/true)) {
        mark_malformed(s, n, "bad module field");
        return;
    }
    if (off >= n || s[off] != ' ') {
        mark_malformed(s, n, "missing separator after module");
        return;
    }
    ++off;

    // ---- Task 2 first: extract speed from lines containing "spd" --------
    // (validated before Task 1 so a corrupt line never pollutes any table)
    const char* msg = s + off;
    const std::size_t msg_len = n - off;
    bool has_spd = false;
    for (std::size_t i = 0; i + 3 <= msg_len; ++i) {
        if (!(msg[i] == 's' && msg[i + 1] == 'p' && msg[i + 2] == 'd'))
            continue;
        const bool left_ok = i == 0 ||
            !((msg[i - 1] >= 'A' && msg[i - 1] <= 'Z') ||
              (msg[i - 1] >= 'a' && msg[i - 1] <= 'z') ||
              is_digit(msg[i - 1]) || msg[i - 1] == '_');
        const bool right_ok = i + 3 == msg_len ||
            !((msg[i + 3] >= 'A' && msg[i + 3] <= 'Z') ||
              (msg[i + 3] >= 'a' && msg[i + 3] <= 'z') ||
              is_digit(msg[i + 3]) || msg[i + 3] == '_');
        if (left_ok && right_ok) { has_spd = true; break; }
    }
    double spd_val = 0.0;
    if (has_spd && !parse_speed(msg, msg_len, spd_val)) {
        // Line claims to carry a speed but the value is corrupted.
        mark_malformed(s, n, "unparsable spd value");
        return;
    }

    // ---- Task 1 aggregation: count(module, hour) ------------------------
    std::string key;
    key.reserve(module.size() + 1 + hour_key.size());
    key += module;
    key.push_back('\x1F');
    key += hour_key;
    auto it = bucket_counts_.find(key);
    if (it != bucket_counts_.end()) {
        ++it->second;
    } else if (bucket_counts_.size() < kMaxBucketEntries) {
        bucket_counts_.emplace(std::move(key), 1);
    } else {
        // Never grow without bound, even if poison lines invent modules.
        bucket_overflow_ = true;
        mark_malformed(s, n, "aggregate table overflow");
        return;
    }

    if (has_spd) {
        if (spd_count_ == 0) { spd_min_ = spd_val; spd_max_ = spd_val; }
        else {
            if (spd_val < spd_min_) spd_min_ = spd_val;
            if (spd_val > spd_max_) spd_max_ = spd_val;
        }
        spd_sum_ += static_cast<long double>(spd_val);
        ++spd_count_;
    }

    ++valid_lines_;
}

bool LogAnalyzer::parse_speed(const char* msg, std::size_t n, double& out) const
{
    std::size_t field_count = 0;
    double parsed = 0.0;
    for (std::size_t i = 0; i + 3 <= n; ++i) {
        if (!(msg[i] == 's' && msg[i + 1] == 'p' && msg[i + 2] == 'd'))
            continue;
        const bool left_ok = i == 0 ||
            !((msg[i - 1] >= 'A' && msg[i - 1] <= 'Z') ||
              (msg[i - 1] >= 'a' && msg[i - 1] <= 'z') ||
              is_digit(msg[i - 1]) || msg[i - 1] == '_');
        const bool right_ok = i + 3 == n ||
            !((msg[i + 3] >= 'A' && msg[i + 3] <= 'Z') ||
              (msg[i + 3] >= 'a' && msg[i + 3] <= 'z') ||
              is_digit(msg[i + 3]) || msg[i + 3] == '_');
        if (!left_ok || !right_ok) continue;
        ++field_count;
        if (field_count > 1) return false; // ambiguous duplicate fields
        std::size_t j = i + 3;
        while (j < n && msg[j] == ' ') ++j;
        if (j >= n || (msg[j] != '=' && msg[j] != ':')) return false;
        ++j;
        while (j < n && msg[j] == ' ') ++j;
        if (j >= n) return false;

        double value = 0.0;
        const auto result = std::from_chars(msg + j, msg + n, value);
        if (result.ec != std::errc()) return false;
        if (result.ptr < msg + n) {
            const char trailing = *result.ptr;
            if (trailing != ' ' && trailing != ',' && trailing != ';' &&
                trailing != '\t')
                return false;
        }
        if (!std::isfinite(value) || value < -100000.0 || value > 100000.0)
            return false;
        parsed = value;
    }
    if (field_count != 1) return false;
    out = parsed;
    return true;
}

void LogAnalyzer::mark_malformed(const char* s, std::size_t n, const char* reason)
{
    ++malformed_lines_;
    if (error_samples_.size() < kMaxErrorSamples) {
        std::string e;
        e.reserve(160);
        e += "line ";
        e += std::to_string(total_lines_);
        e += " [";
        e += reason;
        e += "]: ";
        e += escape_sample(s, n);
        error_samples_.push_back(std::move(e));
    }
}

std::string LogAnalyzer::make_csv() const
{
    // Deterministic ordering for the report: sort by module, then hour.
    std::map<std::string, std::map<std::string, std::uint64_t>> sorted;
    for (const auto& kv : bucket_counts_) {
        const std::size_t sep = kv.first.find('\x1F');
        if (sep == std::string::npos) continue;
        sorted[kv.first.substr(0, sep)][kv.first.substr(sep + 1)] = kv.second;
    }

    std::string csv;
    csv.reserve(64 * 1024);

    csv += "# Task1: event count per module grouped by hour\n";
    csv += "module,hour,count\n";
    for (const auto& mod : sorted) {
        for (const auto& hr : mod.second) {
            csv += csv_escape(mod.first);
            csv += ',';
            csv += csv_escape(hr.first);
            csv += ',';
            csv += std::to_string(hr.second);
            csv += '\n';
        }
    }

    csv += "\n# Task2: average speed over lines containing 'spd'\n";
    csv += "metric,value\n";
    char num[64];
    const double avg = spd_count_ > 0
        ? static_cast<double>(spd_sum_ / static_cast<long double>(spd_count_))
        : 0.0;
    csv += "spd_line_count,";
    csv += std::to_string(spd_count_);
    csv += '\n';
    std::snprintf(num, sizeof(num), "%.6f", avg);
    csv += "average_speed,";
    csv += num;
    csv += '\n';
    std::snprintf(num, sizeof(num), "%.6f", spd_count_ ? spd_min_ : 0.0);
    csv += "min_speed,";
    csv += num;
    csv += '\n';
    std::snprintf(num, sizeof(num), "%.6f", spd_count_ ? spd_max_ : 0.0);
    csv += "max_speed,";
    csv += num;
    csv += '\n';

    csv += "\n# Summary\n";
    csv += "metric,value\n";
    csv += "total_lines,"     + std::to_string(total_lines_)     + "\n";
    csv += "valid_lines,"     + std::to_string(valid_lines_)     + "\n";
    csv += "malformed_lines," + std::to_string(malformed_lines_) + "\n";
    csv += "bytes_processed," + std::to_string(bytes_seen_)      + "\n";
    return csv;
}

std::string LogAnalyzer::summary() const
{
    std::string s;
    s += "lines=" + std::to_string(total_lines_);
    s += " valid=" + std::to_string(valid_lines_);
    s += " malformed=" + std::to_string(malformed_lines_);
    s += " spd_lines=" + std::to_string(spd_count_);
    s += " buckets=" + std::to_string(bucket_counts_.size());
    return s;
}

} // namespace lgx
