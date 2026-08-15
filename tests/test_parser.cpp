// test_parser.cpp - dependency-free unit tests for the streaming LogAnalyzer.
// Covers every poison category from the assignment plus streaming edge cases.
#include "../server/parser.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

static int g_failures = 0;
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
            ++g_failures;                                                  \
        }                                                                  \
    } while (0)

#define CHECK_EQ(a, b)                                                     \
    do {                                                                   \
        const auto va = (a);                                               \
        const auto vb = (b);                                               \
        if (!(va == vb)) {                                                 \
            std::printf("FAIL %s:%d: %s == %s  (%llu vs %llu)\n",          \
                        __FILE__, __LINE__, #a, #b,                        \
                        (unsigned long long)va, (unsigned long long)vb);   \
            ++g_failures;                                                  \
        }                                                                  \
    } while (0)

namespace {

lgx::LogAnalyzer run(const std::string& input, std::size_t chunk = 0)
{
    lgx::LogAnalyzer a;
    if (chunk == 0) {
        a.feed(input.data(), input.size());
    } else {
        for (std::size_t i = 0; i < input.size(); i += chunk) {
            const std::size_t n =
                i + chunk <= input.size() ? chunk : input.size() - i;
            a.feed(input.data() + i, n);
        }
    }
    a.finish();
    return a;
}

const char* kOk1 = "[2026-02-14 08:00:00.000] [INFO] [Engine] spd=10.00 ok\n";
const char* kOk2 = "[2026-02-14 08:00:00.100] [WARN] [Engine] spd=20.00 ok\n";
const char* kOk3 = "[2026-02-14 09:00:00.000] [INFO] [GPS] event=fix\n";

void test_basic_counting()
{
    const auto a = run(std::string(kOk1) + kOk2 + kOk3);
    CHECK_EQ(a.total_lines(), 3u);
    CHECK_EQ(a.valid_lines(), 3u);
    CHECK_EQ(a.malformed_lines(), 0u);
    const std::string csv = a.make_csv();
    CHECK(csv.find("Engine,2026-02-14 08,2") != std::string::npos);
    CHECK(csv.find("GPS,2026-02-14 09,1") != std::string::npos);
    CHECK(csv.find("spd_line_count,2") != std::string::npos);
    CHECK(csv.find("average_speed,15.000000") != std::string::npos);
}

void test_poison_lines_are_skipped_not_fatal()
{
    const std::string poison =
        // missing opening bracket
        "2026-02-14 08:00:00.000] [INFO] [Engine] spd=1.0\n"
        // missing closing bracket on module
        "[2026-02-14 08:00:00.000] [INFO] [Engine event=x\n"
        // binary garbage module
        "[2026-02-14 08:00:00.000] [INFO] [\x01\xFE\x7F] junk\n"
        // truncated / invalid timestamp
        "[2026-02-1 INFO] [Engine] event=stop\n"
        // out-of-range hour
        "[2026-02-14 99:00:00.000] [INFO] [Engine] x\n"
        // unparsable spd value
        "[2026-02-14 08:00:00.000] [INFO] [Engine] spd=NaN?? u\n"
        // trailing junk glued to the number
        "[2026-02-14 08:00:00.000] [INFO] [Engine] spd=12.3x7\n"
        // completely different format
        "{\"ts\":\"2026\",\"spd\":oops}\n"
        // empty module
        "[2026-02-14 08:00:00.000] [INFO] [] x\n";
    const auto a = run(std::string(kOk1) + poison + kOk2);
    CHECK_EQ(a.total_lines(), 11u);
    CHECK_EQ(a.valid_lines(), 2u);
    CHECK_EQ(a.malformed_lines(), 9u);
    const std::string csv = a.make_csv();
    CHECK(csv.find("average_speed,15.000000") != std::string::npos);
    CHECK(a.error_samples().size() == 9u);
}

void test_crlf_and_missing_final_newline()
{
    const auto a = run("[2026-02-14 08:00:00.000] [INFO] [Engine] spd=4.0\r\n"
                       "[2026-02-14 08:00:00.001] [INFO] [Engine] spd=6.0");
    CHECK_EQ(a.valid_lines(), 2u);
    CHECK(a.make_csv().find("average_speed,5.000000") != std::string::npos);
}

void test_empty_input()
{
    const auto a = run("");
    CHECK_EQ(a.total_lines(), 0u);
    CHECK_EQ(a.malformed_lines(), 0u);
    CHECK(a.make_csv().find("total_lines,0") != std::string::npos);
}

void test_overlong_line_bounded_memory()
{
    // 100 KiB single "line" must be discarded without being buffered.
    std::string big(100 * 1024, 'A');
    big += '\n';
    const auto a = run(big + kOk1, /*chunk=*/4096);
    CHECK_EQ(a.valid_lines(), 1u);
    CHECK_EQ(a.malformed_lines(), 1u);
}

void test_chunk_boundary_equivalence()
{
    // Feeding byte-by-byte must give identical results to one-shot feeding.
    const std::string input = std::string(kOk1) +
        "2026 bad line\n" + kOk2 + kOk3 +
        "[2026-02-14 10:30:00.500] [ERROR] [Nav-2.k_x] spd: 42.5 ,tail\n";
    const auto one = run(input);
    const auto tiny = run(input, 1);
    CHECK_EQ(one.total_lines(), tiny.total_lines());
    CHECK_EQ(one.valid_lines(), tiny.valid_lines());
    CHECK_EQ(one.malformed_lines(), tiny.malformed_lines());
    CHECK(one.make_csv() == tiny.make_csv());
    CHECK(one.make_csv().find("Nav-2.k_x,2026-02-14 10,1") != std::string::npos);
}

void test_spd_variants()
{
    const auto a = run(
        "[2026-02-14 08:00:00.000] [INFO] [M] spd = 10\n"      // spaces + '='
        "[2026-02-14 08:00:00.000] [INFO] [M] spd: 20.5\n"     // colon form
        "[2026-02-14 08:00:00.000] [INFO] [M] spd=-8.5 x\n"    // negative
        "[2026-02-14 08:00:00.000] [INFO] [M] spd=1e2\n"       // scientific
        "[2026-02-14 08:00:00.000] [INFO] [M] no speed here\n" // no spd at all
        "[2026-02-14 08:00:00.000] [INFO] [M] spd=inf\n"       // non-finite
        "[2026-02-14 08:00:00.000] [INFO] [M] spd=999999\n");  // absurd range
    // 4 parsable speeds: 10, 20.5, -8.5, 100 -> avg 30.5
    CHECK_EQ(a.valid_lines(), 5u);      // 4 spd lines + "no speed here"
    CHECK_EQ(a.malformed_lines(), 2u);  // inf + out-of-range
    const std::string csv = a.make_csv();
    CHECK(csv.find("spd_line_count,4") != std::string::npos);
    CHECK(csv.find("average_speed,30.500000") != std::string::npos);
    CHECK(csv.find("min_speed,-8.500000") != std::string::npos);
    CHECK(csv.find("max_speed,100.000000") != std::string::npos);
}

void test_aggregate_table_hard_cap()
{
    // Hostile input inventing endless unique modules must hit the cap
    // instead of growing memory without bound.
    lgx::LogAnalyzer a;
    std::string line;
    const std::size_t kInvented = lgx::LogAnalyzer::kMaxBucketEntries + 500;
    for (std::size_t i = 0; i < kInvented; ++i) {
        line = "[2026-02-14 08:00:00.000] [INFO] [M";
        line += std::to_string(i);
        line += "] x\n";
        a.feed(line.data(), line.size());
    }
    a.finish();
    CHECK_EQ(a.valid_lines(), lgx::LogAnalyzer::kMaxBucketEntries);
    CHECK_EQ(a.malformed_lines(), 500u);
}

} // namespace

int main()
{
    test_basic_counting();
    test_poison_lines_are_skipped_not_fatal();
    test_crlf_and_missing_final_newline();
    test_empty_input();
    test_overlong_line_bounded_memory();
    test_chunk_boundary_equivalence();
    test_spd_variants();
    test_aggregate_table_hard_cap();

    if (g_failures == 0) {
        std::printf("ALL PARSER TESTS PASSED\n");
        return 0;
    }
    std::printf("%d FAILURE(S)\n", g_failures);
    return 1;
}
