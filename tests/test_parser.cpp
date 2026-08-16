// test_parser.cpp - self-contained unit tests for the streaming LogAnalyzer.
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
    const std::string input = big + kOk1;
    const auto chunked = run(input, /*chunk=*/4096);
    const auto one_shot = run(input);
    CHECK_EQ(chunked.valid_lines(), 1u);
    CHECK_EQ(chunked.malformed_lines(), 1u);
    CHECK_EQ(one_shot.valid_lines(), 1u);
    CHECK_EQ(one_shot.malformed_lines(), 1u);
    CHECK(chunked.make_csv() == one_shot.make_csv());
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

void test_calendar_blank_and_field_grammar()
{
    const auto a = run(
        "[2026-02-31 08:00:00.000] [INFO] [M] x\n"
        "[2025-02-29 08:00:00.000] [INFO] [M] x\n"
        "[2024-02-29 08:00:00.000] [INFO] [M] x\n"
        "[2026-04-31 08:00:00.000] [INFO] [M] x\n"
        "\n"
        "[2026-02-14 08:00:00.000] [INFO] [M]spd=1\n");
    CHECK_EQ(a.total_lines(), 6u);
    CHECK_EQ(a.valid_lines(), 1u);       // the leap-day line
    CHECK_EQ(a.malformed_lines(), 5u);
}

void test_spd_boundaries_and_duplicates()
{
    const auto a = run(
        "[2026-02-14 08:00:00.000] [INFO] [M] has_spd_marker only\n"
        "[2026-02-14 08:00:00.000] [INFO] [M] xspd=99 telemetry\n"
        "[2026-02-14 08:00:00.000] [INFO] [M] spd=1 spd=BAD\n"
        "[2026-02-14 08:00:00.000] [INFO] [M] spd=12.5 ok\n");
    CHECK_EQ(a.valid_lines(), 3u);       // two unrelated strings + one field
    CHECK_EQ(a.malformed_lines(), 1u);   // ambiguous duplicate
    CHECK(a.make_csv().find("spd_line_count,1") != std::string::npos);
}


void test_byda_assignment_format_and_poison()
{
    const std::string good =
        "[2026-06-19_22:00:00.045000][7710][30482][1885246073] "
        "BYDA::RadarTrackNodeState: nodeUID[47], rfLane[3], lockState[1->0]\n"
        "[2026-06-19_22:00:00.620000][7710][30482][1885246073] "
        "BYDA::BeamSteerCtrlUnitImpl: unitAddr[4181], spd[137500.000000], "
        "advDelta[62750.000000]\n"
        "[2026-06-20_01:00:00.155000][7710][30482][1885246073] "
        "BYDA::DetectionTaskRunner: Sector Command: jobID[7710000000415], "
        "command[RUN], sectorID[20641103], bearing[2]\n";
    const std::string poison =
        "[2026-06-19_22:15:00.000000] !@#$RAW_FRAME_GARBAGE%^&*()\n"
        "2026-06-19_22:20:00.111111][7710][30482][1885246073] "
        "BYDA::HeadBraceLoss: raw[9]\n"
        "[2026-06-19_22:05:00.123456][7710][30482][1885246073 "
        "BYDA::OpenBraceLeak: rfLane[3]\n"
        "[2026-06-19_22:10:00.654321][7710][30482][1885246073] "
        "BYDA::CorruptPayload: nodeUID[NONE], rfLane[X]\n"
        "[2026-06-19_22:25:00.999999][7710][30482][1885246073] "
        "BYDA::BeyondLimit: spd[888888888888888888888.88]\n";

    const auto one = run(good + poison);
    const auto tiny = run(good + poison, 1);
    CHECK_EQ(one.total_lines(), 8u);
    CHECK_EQ(one.valid_lines(), 3u);
    CHECK_EQ(one.malformed_lines(), 5u);
    CHECK(one.make_csv() == tiny.make_csv());
    CHECK(one.make_csv().find(
        "BYDA::RadarTrackNodeState,2026-06-19 22,1") != std::string::npos);
    CHECK(one.make_csv().find(
        "BYDA::DetectionTaskRunner,2026-06-20 01,1") != std::string::npos);
    CHECK(one.make_csv().find("spd_line_count,1") != std::string::npos);
    CHECK(one.make_csv().find("average_speed,137500.000000") !=
          std::string::npos);
}


void test_byda_strict_boundaries()
{
    const auto a = run(
        // Accepted boundary and an unrelated substring.
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: spd[1000000]\n"
        "[2024-02-29_23:59:59.999999][1][2][3] BYDA::M: xspd marker\n"
        // Wrong fractional precision, calendar, metadata, or module grammar.
        "[2026-06-19_22:00:00.00000][1][2][3] BYDA::M: ok\n"
        "[2025-02-29_22:00:00.000000][1][2][3] BYDA::M: ok\n"
        "[2026-06-19_22:00:00.000000][-1][2][3] BYDA::M: ok\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::7M: ok\n"
        "[0000-06-19_22:00:00.000000][1][2][3] BYDA::M: ok\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: \n"
        // BYDA speed must use brackets, be unique, bounded, and complete.
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: spd = 1\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: spd[]\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: spd[1000001]\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: spd[1] spd[2]\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: spd[1x]\n"
        // Typed numeric payloads and printable bytes are enforced.
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: nodeUID[NONE]\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: bad\x01" "byte\n");
    CHECK_EQ(a.total_lines(), 15u);
    CHECK_EQ(a.valid_lines(), 2u);
    CHECK_EQ(a.malformed_lines(), 13u);
    CHECK(a.make_csv().find("spd_line_count,1") != std::string::npos);
    CHECK(a.make_csv().find("average_speed,1000000.000000") !=
          std::string::npos);
}


void test_byda_payload_field_contract()
{
    // A longer field that merely starts with a declared name is a different
    // field and must not be judged by the declared field's contract.
    const auto ok = run(
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: rfLaneCount[3]\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: nodeUIDList[NONE]\n");
    CHECK_EQ(ok.valid_lines(), 2u);
    CHECK_EQ(ok.malformed_lines(), 0u);

    // Every declared integer field is enforced, not just the two that the
    // supplied corpus happens to corrupt.
    const auto bad = run(
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: nodeUID[NONE]\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: rfLane[X]\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: sectorID[NONE]\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: jobID[GARBAGE]\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: bearing[X]\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: unitAddr[?]\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: gatedFlag[Y]\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: element[N][0->1][4]\n");
    CHECK_EQ(bad.valid_lines(), 0u);
    CHECK_EQ(bad.malformed_lines(), 8u);
}

void test_control_bytes_rejected_in_both_dialects()
{
    const auto a = run(
        "[2026-02-14 08:00:00.000] [INFO] [Engine] bad\x01" "payload\n"
        "[2026-06-19_22:00:00.000000][1][2][3] BYDA::M: bad\x01" "payload\n"
        "[2026-02-14 08:00:00.000] [INFO] [Engine] tab\there is fine\n");
    CHECK_EQ(a.valid_lines(), 1u);
    CHECK_EQ(a.malformed_lines(), 2u);
}

void test_aggregate_truncation_is_reported()
{
    lgx::LogAnalyzer a;
    std::string line;
    const std::size_t kInvented = lgx::LogAnalyzer::kMaxBucketEntries + 10;
    for (std::size_t i = 0; i < kInvented; ++i) {
        line = "[2026-02-14 08:00:00.000] [INFO] [M";
        line += std::to_string(i);
        line += "] x\n";
        a.feed(line.data(), line.size());
    }
    a.finish();
    const std::string csv = a.make_csv();
    CHECK(csv.find("aggregate_truncated,1") != std::string::npos);
    CHECK(a.summary().find("AGGREGATE_TRUNCATED") != std::string::npos);

    const auto clean = run(kOk1);
    CHECK(clean.make_csv().find("aggregate_truncated,0") != std::string::npos);
    CHECK(clean.summary().find("AGGREGATE_TRUNCATED") == std::string::npos);
}

void test_byda_envelope_diagnostic()
{
    // A damaged BYDA record must not be reported as a legacy timestamp fault.
    const auto a = run(
        "[2026-06-19_22:05:00.123456][7710][30482][1885246073 "
        "BYDA::OpenBraceLeak: rfLane[3]\n");
    CHECK_EQ(a.malformed_lines(), 1u);
    CHECK(a.error_samples().size() == 1u);
    CHECK(a.error_samples()[0].find("malformed BYDA record envelope") !=
          std::string::npos);
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
    test_calendar_blank_and_field_grammar();
    test_spd_boundaries_and_duplicates();
    test_byda_assignment_format_and_poison();
    test_byda_strict_boundaries();
    test_byda_payload_field_contract();
    test_control_bytes_rejected_in_both_dialects();
    test_aggregate_truncation_is_reported();
    test_byda_envelope_diagnostic();
    test_aggregate_table_hard_cap();

    if (g_failures == 0) {
        std::printf("ALL PARSER TESTS PASSED\n");
        return 0;
    }
    std::printf("%d FAILURE(S)\n", g_failures);
    return 1;
}
