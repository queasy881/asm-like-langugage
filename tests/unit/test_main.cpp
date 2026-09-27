#include "test_framework.h"

#include <cstring>

namespace dctest {
std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}
int g_failures = 0;
const char* g_current = "";

std::string corpusPath(const char* file) { return std::string(DECOMP_CORPUS_DIR) + "/" + file; }
} // namespace dctest

int main(int argc, char** argv) {
    const char* filter = argc > 1 ? argv[1] : nullptr;
    int run = 0, failedTests = 0;
    for (auto& t : dctest::registry()) {
        if (filter && !std::strstr(t.name, filter)) continue;
        int before = dctest::g_failures;
        dctest::g_current = t.name;
        try {
            t.fn();
        } catch (const std::exception& e) {
            std::printf("  FAIL exception: %s\n", e.what());
            ++dctest::g_failures;
        }
        ++run;
        bool ok = dctest::g_failures == before;
        if (!ok) ++failedTests;
        std::printf("[%s] %s\n", ok ? " OK " : "FAIL", t.name);
    }
    std::printf("\n%d tests, %d failed\n", run, failedTests);
    return failedTests ? 1 : 0;
}
