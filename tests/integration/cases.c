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

/* --- control flow, harder shapes ---------------------------------------- */

API int t_early_returns(int a, int b, int c) {
    if (a < 0) return -1;
    if (b < 0) return -2;
    if (c < 0) return -3;
    if (a > b) {
        if (b > c) return a + b + c;
        return a - b;
    }
    if (a == b) return 0;
    return b - a;
}

API int t_loop_two_exits(const int* a, int n, int needle) {
    int i = 0;
    while (i < n) {
        if (a[i] == needle) return i;
        if (a[i] < 0) break;
        i++;
    }
    return -1 - i;
}

API int t_nested_conditions(int x, int y) {
    int r = 0;
    if (x > 0 && y > 0) r = 1;
    else if (x > 0 || y > 0) r = 2;
    else if (x == y) r = 3;
    else r = 4;
    if (x > 100 && y > 100 && x != y) r += 10;
    return r;
}

API int t_while_with_side_effects(int* counter, int n) {
    int total = 0;
    while (n-- > 0) {
        *counter += 1;
        total += *counter;
        if (total > 1000) break;
    }
    return total;
}

API int t_do_while_complex(int n) {
    int a = 1, b = 1;
    do {
        int t = a + b;
        a = b;
        b = t;
        n--;
    } while (n > 0 && b < 100000);
    return b;
}

API int t_triple_nested(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            for (int k = 0; k < n; k++) {
                if ((i + j + k) % 3 == 0) s++;
                else if ((i * j) > 20) s += 2;
            }
        }
    }
    return s;
}

API int t_switch_fallthrough(int op, int x) {
    int r = 0;
    switch (op) {
    case 0:
    case 1:
        r = x + 1;
        break;
    case 2:
        r = x * 2;
        /* fall through */
    case 3:
        r += 100;
        break;
    case 7:
        return x - 1;
    default:
        r = -x;
    }
    return r;
}

API int t_switch_sparse(int op) {
    switch (op) {
    case 1: return 10;
    case 100: return 20;
    case 1000: return 30;
    case 10000: return 40;
    default: return 0;
    }
}

API int t_goto_like(int a, int b) {
    /* A shape that tends to need a goto if structuring gives up. */
    int r = 0;
    if (a > 0) {
        r = 1;
        if (b > 0) goto shared;
        r = 2;
    } else {
        r = 3;
        if (b < 0) goto shared;
        r = 4;
    }
    return r;
shared:
    return r * 10 + a + b;
}

/* --- arithmetic --------------------------------------------------------- */

API int t_mixed_widths(int a, short b, signed char c) {
    return (int)((short)(a + b) * c) + (a >> 3);
}

API unsigned t_unsigned_ops(unsigned a, unsigned b) {
    unsigned r = a + b;
    r ^= a >> 3;
    r |= b << 2;
    r &= 0xFFFF00FFu;
    if (r > a) r -= a;
    return r / (b | 1);
}

API int t_div_by_constants(int x) {
    return x / 3 + x / 7 + x % 5 - x / 256;
}

API unsigned t_udiv_by_constants(unsigned x) {
    return x / 3u + x / 10u + x % 7u;
}

API int64_t t_mul_high(int64_t a, int64_t b) { return (a * b) >> 32; }

API int t_shift_chain(int x, int n) {
    n &= 31;
    return (x << n) | ((unsigned)x >> (32 - n ? 32 - n : 0));
}

API int t_abs_and_min_max(int a, int b) {
    int x = a < 0 ? -a : a;
    int lo = a < b ? a : b;
    int hi = a > b ? a : b;
    return x + lo * 2 + hi * 3;
}

API int t_bool_logic(int a, int b, int c) {
    int r = 0;
    r |= (a > 0) ? 1 : 0;
    r |= (b > 0 && c > 0) ? 2 : 0;
    r |= (a == b) ? 4 : 0;
    r |= (!a) ? 8 : 0;
    return r;
}

API int64_t t_sign_extension(int a, short b, signed char c) {
    return (int64_t)a + (int64_t)b + (int64_t)c;
}

API uint64_t t_zero_extension(unsigned a, unsigned short b, unsigned char c) {
    return (uint64_t)a + (uint64_t)b + (uint64_t)c;
}

/* --- calls -------------------------------------------------------------- */

static int leaf_a(int x) { return x + 1; }
static int leaf_b(int x) { return x * 2; }
static int leaf_c(int x, int y) { return x - y; }

API int t_call_chain(int x) { return leaf_c(leaf_a(x), leaf_b(x)); }

API int t_call_in_loop(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += leaf_a(i) + leaf_b(i);
    return s;
}

API int t_call_in_condition(int x) {
    if (leaf_a(x) > 10) return leaf_b(x);
    return leaf_c(x, 3);
}

typedef int (*IntFn)(int);
API int t_function_pointer(int which, int x) {
    IntFn f = which ? leaf_a : leaf_b;
    return f(x) + f(x + 1);
}

API int t_call_with_many(int a, int b, int c, int d, int e, int f, int g, int h) {
    return t_many_args(a, b, c, d, e, f) + g * 7 + h * 8;
}

API int t_deep_recursion(int n) {
    if (n <= 0) return 0;
    if (n == 1) return 1;
    return t_deep_recursion(n - 1) + t_deep_recursion(n - 2);
}

/* --- pointers and structs ----------------------------------------------- */

struct Node {
    int value;
    int pad;
    struct Node* next;
};

API int t_walk_list(struct Node* head, int limit) {
    int s = 0;
    while (head && limit-- > 0) {
        s += head->value;
        head = head->next;
    }
    return s;
}

struct Wide {
    unsigned char a;
    short b;
    int c;
    int64_t d;
    float e;
    double f;
};

API int t_wide_struct(struct Wide* w) {
    return (int)w->a + w->b + w->c + (int)w->d + (int)w->e + (int)w->f;
}

API void t_wide_struct_write(struct Wide* w, int v) {
    w->a = (unsigned char)v;
    w->b = (short)(v * 2);
    w->c = v * 3;
    w->d = (int64_t)v * 4;
    w->e = (float)v;
    w->f = (double)v * 0.5;
}

API int t_array_of_structs(struct Point* pts, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += pts[i].x * pts[i].y + (int)pts[i].tag;
    return s;
}

API int t_pointer_compare(const int* a, const int* b) {
    if (a == b) return 0;
    if (a < b) return -1;
    return 1;
}

API int t_two_dim(const int* m, int rows, int cols) {
    int s = 0;
    for (int r = 0; r < rows; r++)
        for (int c = 0; c < cols; c++)
            s += m[r * cols + c] * (r + c);
    return s;
}
