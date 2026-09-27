// Minimal self-contained unit test framework (no external dependencies).
#pragma once

#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace dctest {

struct TestCase {
    const char* name;
    std::function<void()> fn;
};

std::vector<TestCase>& registry();
extern int g_failures;
extern const char* g_current;

struct Registrar {
    Registrar(const char* name, std::function<void()> fn) { registry().push_back({name, std::move(fn)}); }
};

std::string corpusPath(const char* file);

} // namespace dctest

#define DC_CONCAT2(a, b) a##b
#define DC_CONCAT(a, b) DC_CONCAT2(a, b)
#define TEST(name)                                                              \
    static void DC_CONCAT(test_fn_, name)();                                    \
    static ::dctest::Registrar DC_CONCAT(test_reg_, name)(#name, DC_CONCAT(test_fn_, name)); \
    static void DC_CONCAT(test_fn_, name)()

#define CHECK(cond)                                                                        \
    do {                                                                                   \
        if (!(cond)) {                                                                     \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                   \
            ++::dctest::g_failures;                                                        \
        }                                                                                  \
    } while (0)

#define CHECK_EQ(a, b)                                                                     \
    do {                                                                                   \
        auto _va = (a);                                                                    \
        auto _vb = (b);                                                                    \
        if (!(_va == _vb)) {                                                               \
            std::ostringstream _os;                                                        \
            _os << _va << " != " << _vb;                                                   \
            std::printf("  FAIL %s:%d: %s == %s (%s)\n", __FILE__, __LINE__, #a, #b, _os.str().c_str()); \
            ++::dctest::g_failures;                                                        \
        }                                                                                  \
    } while (0)

#define REQUIRE(cond)                                                                      \
    do {                                                                                   \
        if (!(cond)) {                                                                     \
            std::printf("  FAIL (fatal) %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
            ++::dctest::g_failures;                                                        \
            return;                                                                        \
        }                                                                                  \
    } while (0)
