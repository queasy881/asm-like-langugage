/* Test programs compiled both natively (as the reference) and with MinGW into
 * PE images for the decompiler to recover. Every function here must be
 * self-contained and deterministic. */

#include <stdint.h>

#ifdef DECOMP_EXPORT
#define API __declspec(dllexport)
#else
#define API
#endif

/* --- plain arithmetic --------------------------------------------------- */

API int t_add(int a, int b) { return a + b; }

API int t_branch(int x) {
    if (x > 10) return x * 2;
    return x + 5;
}

API int t_ifelse_chain(int x) {
    if (x < 0) return -1;
    else if (x == 0) return 0;
    else if (x < 10) return 1;
    else if (x < 100) return 2;
    return 3;
}

API int t_for_loop(int n) {
    int result = 0;
    for (int i = 0; i < n; i++) result += i;
    return result;
}

API int t_while_loop(int n) {
    int r = 1;
    while (n > 1) {
        r *= n;
        n--;
    }
    return r;
}

API int t_do_while(int n) {
    int c = 0;
    do {
        n >>= 1;
        c++;
    } while (n);
    return c;
}

API int t_nested_loops(int n) {
    int total = 0;
    for (int i = 0; i < n; i++)
        for (int j = 0; j < i; j++)
            total += i * j;
    return total;
}

API int t_continue_break(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if ((i & 1) == 0) continue;
        if (i > 50) break;
        s += i;
    }
    return s;
}

API int t_switch(int op, int a, int b) {
    switch (op) {
    case 0: return a + b;
    case 1: return a - b;
    case 2: return a * b;
    case 3: return b ? a / b : -1;
    case 4: return a & b;
    case 5: return a | b;
    case 6: return a ^ b;
    case 7: return a << (b & 31);
    case 8: return a >> (b & 31);
    default: return 0;
    }
}

API unsigned t_bitops(unsigned x) {
    x = ((x >> 1) & 0x55555555u) | ((x & 0x55555555u) << 1);
    x = ((x >> 2) & 0x33333333u) | ((x & 0x33333333u) << 2);
    x ^= x >> 16;
    return x * 2654435761u;
}

API int64_t t_wide(int64_t a, int64_t b) {
    int64_t s = a * b;
    if (s < 0) s = -s;
    return s % 1000000007;
}

API unsigned t_udiv(unsigned a, unsigned b) { return b ? a / b + a % b : 0u; }
API int t_sdiv(int a, int b) { return b ? a / b + a % b : 0; }

API int t_signed_compare(int a, int b) {
    int r = 0;
    if (a < b) r |= 1;
    if (a <= b) r |= 2;
    if (a > b) r |= 4;
    if (a >= b) r |= 8;
    if (a == b) r |= 16;
    if ((unsigned)a < (unsigned)b) r |= 32;
    return r;
}

/* --- floating point ----------------------------------------------------- */

API float t_float(float a, float b) { return a * b + a / (b == 0.0f ? 1.0f : b); }
API double t_double(double a, double b) { return (a + b) * (a - b); }
API int t_float_compare(float a, float b) { return a < b ? -1 : (a > b ? 1 : 0); }
API double t_int_to_double(int x) { return (double)x * 0.5 + 1.0; }
API int t_double_to_int(double x) { return (int)(x * 3.0); }

/* --- memory and structs ------------------------------------------------- */

struct Point {
    int x;
    int y;
    int64_t tag;
};

API int t_struct_sum(struct Point* p) { return p->x + p->y + (int)p->tag; }

API void t_struct_write(struct Point* p, int x, int y) {
    p->x = x;
    p->y = y;
    p->tag = (int64_t)x * y;
}

API int t_array_sum(const int* a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i];
    return s;
}

API int t_array_max(const int* a, int n) {
    if (n <= 0) return 0;
    int m = a[0];
    for (int i = 1; i < n; i++)
        if (a[i] > m) m = a[i];
    return m;
}

API void t_array_reverse(int* a, int n) {
    for (int i = 0, j = n - 1; i < j; i++, j--) {
        int t = a[i];
        a[i] = a[j];
        a[j] = t;
    }
}

API int t_strlen(const char* s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

API int t_local_array(int n) {
    int buf[16];
    for (int i = 0; i < 16; i++) buf[i] = i * n;
    int s = 0;
    for (int i = 0; i < 16; i++) s += buf[i];
    return s;
}

/* --- calls and recursion ------------------------------------------------ */

static int helper(int x) { return x * 3 + 1; }

API int t_call_helper(int a, int b) { return helper(a) + helper(b); }

API int t_recursion(int n) {
    if (n <= 1) return 1;
    return n * t_recursion(n - 1);
}

API int t_mutual_a(int n);
API int t_mutual_b(int n) { return n <= 0 ? 0 : t_mutual_a(n - 1) + 2; }
API int t_mutual_a(int n) { return n <= 0 ? 1 : t_mutual_b(n - 1) + 1; }

API int t_many_args(int a, int b, int c, int d, int e, int f) {
    return a * 1 + b * 2 + c * 3 + d * 4 + e * 5 + f * 6;
}

/* --- pointer walking ---------------------------------------------------- */

API unsigned t_hash_bytes(const unsigned char* data, int len) {
    unsigned h = 2166136261u;
    for (int i = 0; i < len; i++) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

API int t_find_byte(const unsigned char* data, int len, int value) {
    for (int i = 0; i < len; i++)
        if (data[i] == (unsigned char)value) return i;
    return -1;
}
