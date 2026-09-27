/* A corpus of long functions. Every function here is between roughly one and
 * two hundred lines of source, which is where a decompiler starts to be
 * tested in earnest: dozens of live values at once, deeply nested loops,
 * switches with many arms, structs passed by pointer, and mixed integer and
 * floating point arithmetic in the same frame.
 *
 * Nothing here calls the C library, so the whole corpus can be run inside the
 * IR interpreter with no host support. */

#include <stdint.h>

#ifdef DECOMP_EXPORT
#define API __declspec(dllexport)
#else
#define API
#endif

/* ------------------------------------------------------------------ */
/* 1. A JSON-ish scanner producing a flat token array.                  */

enum {
    JT_END = 0, JT_OBJ_OPEN, JT_OBJ_CLOSE, JT_ARR_OPEN, JT_ARR_CLOSE,
    JT_COLON, JT_COMMA, JT_STRING, JT_NUMBER, JT_TRUE, JT_FALSE, JT_NULL
};

struct JsonToken {
    int32_t kind;
    int32_t start;
    int32_t length;
    int32_t depth;
};

API int json_scan(const char* text, int len, struct JsonToken* out, int cap)
{
    int pos = 0;
    int count = 0;
    int depth = 0;
    int maxDepth = 0;
    int errors = 0;

    if (len < 0 || cap <= 0)
        return -1;

    while (pos < len) {
        char c = text[pos];
        int kind = JT_END;
        int start = pos;
        int length = 1;

        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            pos++;
            continue;
        }

        switch (c) {
        case '{':
            kind = JT_OBJ_OPEN;
            depth++;
            if (depth > maxDepth)
                maxDepth = depth;
            pos++;
            break;
        case '}':
            kind = JT_OBJ_CLOSE;
            depth--;
            if (depth < 0)
                errors++;
            pos++;
            break;
        case '[':
            kind = JT_ARR_OPEN;
            depth++;
            if (depth > maxDepth)
                maxDepth = depth;
            pos++;
            break;
        case ']':
            kind = JT_ARR_CLOSE;
            depth--;
            if (depth < 0)
                errors++;
            pos++;
            break;
        case ':':
            kind = JT_COLON;
            pos++;
            break;
        case ',':
            kind = JT_COMMA;
            pos++;
            break;
        case '"': {
            int p = pos + 1;
            int closed = 0;
            while (p < len) {
                char d = text[p];
                if (d == '\\') {
                    p += 2;
                    continue;
                }
                if (d == '"') {
                    closed = 1;
                    break;
                }
                p++;
            }
            if (!closed) {
                errors++;
                pos = len;
                length = len - start;
            } else {
                length = p + 1 - start;
                pos = p + 1;
            }
            kind = JT_STRING;
            break;
        }
        default:
            if (c == '-' || (c >= '0' && c <= '9')) {
                int p = pos;
                int seenDot = 0;
                int seenExp = 0;
                if (text[p] == '-')
                    p++;
                while (p < len) {
                    char d = text[p];
                    if (d >= '0' && d <= '9') {
                        p++;
                    } else if (d == '.' && !seenDot && !seenExp) {
                        seenDot = 1;
                        p++;
                    } else if ((d == 'e' || d == 'E') && !seenExp) {
                        seenExp = 1;
                        p++;
                        if (p < len && (text[p] == '+' || text[p] == '-'))
                            p++;
                    } else {
                        break;
                    }
                }
                kind = JT_NUMBER;
                length = p - start;
                pos = p;
            } else if (c == 't' && pos + 4 <= len && text[pos + 1] == 'r' &&
                       text[pos + 2] == 'u' && text[pos + 3] == 'e') {
                kind = JT_TRUE;
                length = 4;
                pos += 4;
            } else if (c == 'f' && pos + 5 <= len && text[pos + 1] == 'a' &&
                       text[pos + 2] == 'l' && text[pos + 3] == 's' && text[pos + 4] == 'e') {
                kind = JT_FALSE;
                length = 5;
                pos += 5;
            } else if (c == 'n' && pos + 4 <= len && text[pos + 1] == 'u' &&
                       text[pos + 2] == 'l' && text[pos + 3] == 'l') {
                kind = JT_NULL;
                length = 4;
                pos += 4;
            } else {
                errors++;
                pos++;
                continue;
            }
            break;
        }

        if (count < cap) {
            out[count].kind = kind;
            out[count].start = start;
            out[count].length = length;
            out[count].depth = depth;
            count++;
        } else {
            errors++;
        }
    }

    if (depth != 0)
        errors++;
    if (errors)
        return -(errors + 1);
    return count;
}

/* ------------------------------------------------------------------ */
/* 2. Gaussian elimination with partial pivoting, in place.             */

API int matrix_solve(double* a, double* b, int n, double* x)
{
    int i, j, k;
    int swaps = 0;
    int singular = 0;

    if (n <= 0 || n > 16)
        return -1;

    for (k = 0; k < n; k++) {
        int pivot = k;
        double best = a[k * n + k];
        if (best < 0.0)
            best = -best;

        for (i = k + 1; i < n; i++) {
            double v = a[i * n + k];
            if (v < 0.0)
                v = -v;
            if (v > best) {
                best = v;
                pivot = i;
            }
        }

        if (best < 1e-12) {
            singular = 1;
            continue;
        }

        if (pivot != k) {
            for (j = 0; j < n; j++) {
                double t = a[k * n + j];
                a[k * n + j] = a[pivot * n + j];
                a[pivot * n + j] = t;
            }
            {
                double t = b[k];
                b[k] = b[pivot];
                b[pivot] = t;
            }
            swaps++;
        }

        for (i = k + 1; i < n; i++) {
            double factor = a[i * n + k] / a[k * n + k];
            if (factor == 0.0)
                continue;
            a[i * n + k] = 0.0;
            for (j = k + 1; j < n; j++)
                a[i * n + j] -= factor * a[k * n + j];
            b[i] -= factor * b[k];
        }
    }

    if (singular)
        return -2;

    for (i = n - 1; i >= 0; i--) {
        double sum = b[i];
        for (j = i + 1; j < n; j++)
            sum -= a[i * n + j] * x[j];
        x[i] = sum / a[i * n + i];
    }

    return swaps;
}

/* ------------------------------------------------------------------ */
/* 3. Huffman code lengths from symbol frequencies.                     */

struct HuffNode {
    int32_t freq;
    int32_t left;
    int32_t right;
    int32_t parent;
};

API int huffman_lengths(const int32_t* freq, int nsym, uint8_t* lengths, struct HuffNode* pool, int poolCap)
{
    int i;
    int nodes = 0;
    int live = 0;
    int maxLen = 0;
    int total = 0;

    if (nsym <= 0 || poolCap < nsym * 2)
        return -1;

    for (i = 0; i < nsym; i++) {
        lengths[i] = 0;
        if (freq[i] <= 0)
            continue;
        pool[nodes].freq = freq[i];
        pool[nodes].left = -1;
        pool[nodes].right = -1;
        pool[nodes].parent = -1;
        nodes++;
        live++;
        total += freq[i];
    }

    if (live == 0)
        return 0;
    if (live == 1) {
        for (i = 0; i < nsym; i++)
            if (freq[i] > 0)
                lengths[i] = 1;
        return 1;
    }

    while (live > 1) {
        int a = -1;
        int bIdx = -1;
        for (i = 0; i < nodes; i++) {
            if (pool[i].parent != -1)
                continue;
            if (a < 0 || pool[i].freq < pool[a].freq) {
                bIdx = a;
                a = i;
            } else if (bIdx < 0 || pool[i].freq < pool[bIdx].freq) {
                bIdx = i;
            }
        }
        if (a < 0 || bIdx < 0)
            break;
        if (nodes >= poolCap)
            return -2;

        pool[nodes].freq = pool[a].freq + pool[bIdx].freq;
        pool[nodes].left = a;
        pool[nodes].right = bIdx;
        pool[nodes].parent = -1;
        pool[a].parent = nodes;
        pool[bIdx].parent = nodes;
        nodes++;
        live--;
    }

    {
        int leaf = 0;
        for (i = 0; i < nsym; i++) {
            int depth = 0;
            int at;
            if (freq[i] <= 0)
                continue;
            at = leaf;
            while (pool[at].parent != -1) {
                at = pool[at].parent;
                depth++;
                if (depth > 64)
                    return -3;
            }
            if (depth > 255)
                depth = 255;
            lengths[i] = (uint8_t)depth;
            if (depth > maxLen)
                maxLen = depth;
            leaf++;
        }
    }

    if (total <= 0)
        return -4;
    return maxLen;
}

/* ------------------------------------------------------------------ */
/* 4. Run-length codec: one function that both encodes and decodes.     */

API int rle_codec(const uint8_t* in, int inLen, uint8_t* out, int outCap, int decode)
{
    int rp = 0;
    int wp = 0;
    int runs = 0;

    if (inLen < 0 || outCap <= 0)
        return -1;

    if (decode) {
        while (rp < inLen) {
            uint8_t hdr = in[rp++];
            int n;
            if (hdr & 0x80) {
                n = (hdr & 0x7F) + 1;
                if (rp >= inLen)
                    return -2;
                {
                    uint8_t value = in[rp++];
                    int i;
                    if (wp + n > outCap)
                        return -3;
                    for (i = 0; i < n; i++)
                        out[wp + i] = value;
                    wp += n;
                }
            } else {
                int i;
                n = hdr + 1;
                if (rp + n > inLen)
                    return -2;
                if (wp + n > outCap)
                    return -3;
                for (i = 0; i < n; i++)
                    out[wp + i] = in[rp + i];
                rp += n;
                wp += n;
            }
            runs++;
        }
        return wp;
    }

    while (rp < inLen) {
        uint8_t first = in[rp];
        int run = 1;
        while (rp + run < inLen && in[rp + run] == first && run < 128)
            run++;

        if (run >= 3) {
            if (wp + 2 > outCap)
                return -3;
            out[wp++] = (uint8_t)(0x80 | (run - 1));
            out[wp++] = first;
            rp += run;
            runs++;
            continue;
        }

        {
            int lit = 0;
            int startRp = rp;
            while (rp < inLen && lit < 128) {
                int same = 1;
                while (rp + same < inLen && in[rp + same] == in[rp] && same < 4)
                    same++;
                if (same >= 3)
                    break;
                rp++;
                lit++;
            }
            if (lit == 0) {
                rp = startRp + 1;
                lit = 1;
            }
            if (wp + 1 + lit > outCap)
                return -3;
            out[wp++] = (uint8_t)(lit - 1);
            {
                int i;
                for (i = 0; i < lit; i++)
                    out[wp + i] = in[startRp + i];
            }
            wp += lit;
            runs++;
        }
    }

    return wp;
}

/* ------------------------------------------------------------------ */
/* 5. Bitset algebra over a fixed number of 64-bit words.               */

API int bitset_ops(uint64_t* dst, const uint64_t* src, int words, int op, int32_t* stats)
{
    int i;
    int popcount = 0;
    int firstSet = -1;
    int lastSet = -1;
    int changed = 0;

    if (words <= 0 || words > 64)
        return -1;

    for (i = 0; i < words; i++) {
        uint64_t before = dst[i];
        uint64_t other = src ? src[i] : 0;
        uint64_t after;

        switch (op) {
        case 0: after = before | other; break;
        case 1: after = before & other; break;
        case 2: after = before ^ other; break;
        case 3: after = before & ~other; break;
        case 4: after = ~before; break;
        case 5:
            after = (before << 1) | (i > 0 ? (dst[i - 1] >> 63) : 0);
            break;
        case 6:
            after = (before >> 1) | (i + 1 < words ? (dst[i + 1] << 63) : 0);
            break;
        default:
            return -2;
        }

        if (after != before)
            changed++;
        dst[i] = after;
    }

    for (i = 0; i < words; i++) {
        uint64_t w = dst[i];
        int bit;
        if (w == 0)
            continue;
        for (bit = 0; bit < 64; bit++) {
            if (((w >> bit) & 1) == 0)
                continue;
            popcount++;
            if (firstSet < 0)
                firstSet = i * 64 + bit;
            lastSet = i * 64 + bit;
        }
    }

    if (stats) {
        int runs = 0;
        int inRun = 0;
        stats[0] = popcount;
        stats[1] = firstSet;
        stats[2] = lastSet;
        stats[3] = changed;
        for (i = 0; i < words * 64; i++) {
            int bit = (int)((dst[i >> 6] >> (i & 63)) & 1);
            if (bit && !inRun) {
                runs++;
                inRun = 1;
            } else if (!bit) {
                inRun = 0;
            }
        }
        stats[4] = runs;
    }

    return popcount;
}

/* ------------------------------------------------------------------ */
/* 6. The SHA-256 compression function over one 64-byte block.          */

static const uint32_t kSha256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

API void sha256_block(uint32_t* state, const uint8_t* block, uint32_t* scratch)
{
    uint32_t a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++) {
        scratch[i] = ((uint32_t)block[i * 4] << 24) |
                     ((uint32_t)block[i * 4 + 1] << 16) |
                     ((uint32_t)block[i * 4 + 2] << 8) |
                     ((uint32_t)block[i * 4 + 3]);
    }

    for (i = 16; i < 64; i++) {
        uint32_t w15 = scratch[i - 15];
        uint32_t w2 = scratch[i - 2];
        uint32_t s0 = ((w15 >> 7) | (w15 << 25)) ^ ((w15 >> 18) | (w15 << 14)) ^ (w15 >> 3);
        uint32_t s1 = ((w2 >> 17) | (w2 << 15)) ^ ((w2 >> 19) | (w2 << 13)) ^ (w2 >> 10);
        scratch[i] = scratch[i - 16] + s0 + scratch[i - 7] + s1;
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + kSha256[i] + scratch[i];
        uint32_t S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

/* ------------------------------------------------------------------ */
/* 7. A small stack machine with typed values.                          */

enum {
    OP_HALT = 0, OP_PUSHI, OP_PUSHF, OP_ADD, OP_SUB, OP_MUL, OP_DIV,
    OP_NEG, OP_CMP, OP_JMP, OP_JZ, OP_JNZ, OP_LOAD, OP_STORE,
    OP_DUP, OP_SWAP, OP_DROP, OP_TOINT, OP_TOFLOAT, OP_PRINT
};

struct Value {
    int32_t isFloat;
    int32_t ival;
    double fval;
};

API int interp_eval(const int32_t* code, int codeLen, struct Value* stack, int stackCap,
                    struct Value* slots, int slotCount, int32_t* trace)
{
    int pc = 0;
    int sp = 0;
    int steps = 0;
    int printed = 0;

    if (codeLen <= 0 || stackCap < 4 || slotCount < 0)
        return -1;

    while (pc < codeLen) {
        int op = code[pc];
        if (++steps > 100000)
            return -9;
        if (trace)
            trace[0] = steps;
        pc++;

        switch (op) {
        case OP_HALT:
            return sp;

        case OP_PUSHI:
            if (pc >= codeLen || sp >= stackCap)
                return -2;
            stack[sp].isFloat = 0;
            stack[sp].ival = code[pc];
            stack[sp].fval = 0.0;
            sp++;
            pc++;
            break;

        case OP_PUSHF:
            if (pc >= codeLen || sp >= stackCap)
                return -2;
            stack[sp].isFloat = 1;
            stack[sp].ival = 0;
            stack[sp].fval = (double)code[pc] / 1000.0;
            sp++;
            pc++;
            break;

        case OP_ADD:
        case OP_SUB:
        case OP_MUL:
        case OP_DIV: {
            struct Value lhs, rhs, res;
            if (sp < 2)
                return -3;
            rhs = stack[--sp];
            lhs = stack[--sp];
            res.isFloat = lhs.isFloat | rhs.isFloat;
            res.ival = 0;
            res.fval = 0.0;
            if (res.isFloat) {
                double l = lhs.isFloat ? lhs.fval : (double)lhs.ival;
                double r = rhs.isFloat ? rhs.fval : (double)rhs.ival;
                if (op == OP_ADD) res.fval = l + r;
                else if (op == OP_SUB) res.fval = l - r;
                else if (op == OP_MUL) res.fval = l * r;
                else {
                    if (r == 0.0)
                        return -4;
                    res.fval = l / r;
                }
            } else {
                if (op == OP_ADD) res.ival = lhs.ival + rhs.ival;
                else if (op == OP_SUB) res.ival = lhs.ival - rhs.ival;
                else if (op == OP_MUL) res.ival = lhs.ival * rhs.ival;
                else {
                    if (rhs.ival == 0)
                        return -4;
                    res.ival = lhs.ival / rhs.ival;
                }
            }
            stack[sp++] = res;
            break;
        }

        case OP_NEG:
            if (sp < 1)
                return -3;
            if (stack[sp - 1].isFloat)
                stack[sp - 1].fval = -stack[sp - 1].fval;
            else
                stack[sp - 1].ival = -stack[sp - 1].ival;
            break;

        case OP_CMP: {
            struct Value lhs, rhs;
            int r;
            if (sp < 2)
                return -3;
            rhs = stack[--sp];
            lhs = stack[--sp];
            if (lhs.isFloat || rhs.isFloat) {
                double l = lhs.isFloat ? lhs.fval : (double)lhs.ival;
                double rr = rhs.isFloat ? rhs.fval : (double)rhs.ival;
                r = l < rr ? -1 : (l > rr ? 1 : 0);
            } else {
                r = lhs.ival < rhs.ival ? -1 : (lhs.ival > rhs.ival ? 1 : 0);
            }
            stack[sp].isFloat = 0;
            stack[sp].ival = r;
            stack[sp].fval = 0.0;
            sp++;
            break;
        }

        case OP_JMP:
        case OP_JZ:
        case OP_JNZ: {
            int target;
            if (pc >= codeLen)
                return -2;
            target = code[pc];
            pc++;
            if (target < 0 || target >= codeLen)
                return -5;
            if (op == OP_JMP) {
                pc = target;
            } else {
                int cond;
                if (sp < 1)
                    return -3;
                sp--;
                cond = stack[sp].isFloat ? (stack[sp].fval != 0.0) : (stack[sp].ival != 0);
                if ((op == OP_JZ && !cond) || (op == OP_JNZ && cond))
                    pc = target;
            }
            break;
        }

        case OP_LOAD:
        case OP_STORE: {
            int slot;
            if (pc >= codeLen)
                return -2;
            slot = code[pc];
            pc++;
            if (slot < 0 || slot >= slotCount)
                return -6;
            if (op == OP_LOAD) {
                if (sp >= stackCap)
                    return -2;
                stack[sp++] = slots[slot];
            } else {
                if (sp < 1)
                    return -3;
                slots[slot] = stack[--sp];
            }
            break;
        }

        case OP_DUP:
            if (sp < 1 || sp >= stackCap)
                return -3;
            stack[sp] = stack[sp - 1];
            sp++;
            break;

        case OP_SWAP: {
            struct Value t;
            if (sp < 2)
                return -3;
            t = stack[sp - 1];
            stack[sp - 1] = stack[sp - 2];
            stack[sp - 2] = t;
            break;
        }

        case OP_DROP:
            if (sp < 1)
                return -3;
            sp--;
            break;

        case OP_TOINT:
            if (sp < 1)
                return -3;
            if (stack[sp - 1].isFloat) {
                stack[sp - 1].ival = (int32_t)stack[sp - 1].fval;
                stack[sp - 1].fval = 0.0;
                stack[sp - 1].isFloat = 0;
            }
            break;

        case OP_TOFLOAT:
            if (sp < 1)
                return -3;
            if (!stack[sp - 1].isFloat) {
                stack[sp - 1].fval = (double)stack[sp - 1].ival;
                stack[sp - 1].ival = 0;
                stack[sp - 1].isFloat = 1;
            }
            break;

        case OP_PRINT:
            if (sp < 1)
                return -3;
            if (trace)
                trace[1 + (printed & 7)] = stack[sp - 1].isFloat
                                               ? (int32_t)stack[sp - 1].fval
                                               : stack[sp - 1].ival;
            printed++;
            sp--;
            break;

        default:
            return -7;
        }
    }

    return sp;
}

/* ------------------------------------------------------------------ */
/* 8. A skip list over a caller-supplied node arena.                    */

#define SKIP_LEVELS 8

struct SkipNode {
    int32_t key;
    int32_t value;
    int32_t next[SKIP_LEVELS];
};

API int skiplist_ops(struct SkipNode* arena, int32_t* header, int cap, const int32_t* ops,
                     int opCount, int32_t* results)
{
    int used = header[0];
    int level = header[1];
    uint32_t rng = (uint32_t)header[2];
    int i;
    int found = 0;
    int inserted = 0;

    if (cap <= 0 || opCount < 0)
        return -1;
    if (level < 1)
        level = 1;
    if (used < 1) {
        arena[0].key = -2147483647 - 1;
        arena[0].value = 0;
        for (i = 0; i < SKIP_LEVELS; i++)
            arena[0].next[i] = -1;
        used = 1;
    }

    for (i = 0; i < opCount; i++) {
        int kind = ops[i * 3];
        int key = ops[i * 3 + 1];
        int value = ops[i * 3 + 2];
        int update[SKIP_LEVELS];
        int at = 0;
        int lv;

        for (lv = level - 1; lv >= 0; lv--) {
            int nxt = arena[at].next[lv];
            while (nxt >= 0 && arena[nxt].key < key) {
                at = nxt;
                nxt = arena[at].next[lv];
            }
            update[lv] = at;
        }

        {
            int cand = arena[at].next[0];
            int hit = (cand >= 0 && arena[cand].key == key) ? cand : -1;

            if (kind == 0) {
                if (results)
                    results[i] = hit >= 0 ? arena[hit].value : -1;
                if (hit >= 0)
                    found++;
                continue;
            }

            if (kind == 2) {
                if (hit < 0) {
                    if (results)
                        results[i] = -1;
                    continue;
                }
                for (lv = 0; lv < level; lv++) {
                    if (arena[update[lv]].next[lv] != hit)
                        break;
                    arena[update[lv]].next[lv] = arena[hit].next[lv];
                }
                while (level > 1 && arena[0].next[level - 1] < 0)
                    level--;
                if (results)
                    results[i] = arena[hit].value;
                continue;
            }

            if (hit >= 0) {
                arena[hit].value = value;
                if (results)
                    results[i] = 0;
                continue;
            }

            if (used >= cap)
                return -2;

            {
                int newLevel = 1;
                int node;
                rng ^= rng << 13;
                rng ^= rng >> 17;
                rng ^= rng << 5;
                while ((rng & 3) == 0 && newLevel < SKIP_LEVELS) {
                    newLevel++;
                    rng = rng * 1664525u + 1013904223u;
                }
                if (newLevel > level) {
                    for (lv = level; lv < newLevel; lv++)
                        update[lv] = 0;
                    level = newLevel;
                }

                node = used++;
                arena[node].key = key;
                arena[node].value = value;
                for (lv = 0; lv < SKIP_LEVELS; lv++)
                    arena[node].next[lv] = -1;
                for (lv = 0; lv < newLevel; lv++) {
                    arena[node].next[lv] = arena[update[lv]].next[lv];
                    arena[update[lv]].next[lv] = node;
                }
                inserted++;
                if (results)
                    results[i] = 1;
            }
        }
    }

    header[0] = used;
    header[1] = level;
    header[2] = (int32_t)rng;
    header[3] = found;
    header[4] = inserted;
    return used;
}

/* ------------------------------------------------------------------ */
/* 9. CSV record splitting with quoting, trimming and numeric fields.   */

struct CsvField {
    int32_t start;
    int32_t length;
    int32_t isNumber;
    int32_t number;
};

API int csv_parse(const char* text, int len, struct CsvField* fields, int cap, int32_t* rowCount)
{
    int pos = 0;
    int count = 0;
    int rows = 0;
    int bad = 0;
    int atLineStart = 1;

    if (len < 0 || cap <= 0)
        return -1;

    while (pos <= len) {
        int start;
        int end;
        int quoted = 0;
        int isNumber;
        int number = 0;
        int sign = 1;
        int digits = 0;
        int j;

        if (pos == len && !atLineStart)
            break;
        if (pos == len && atLineStart)
            break;

        while (pos < len && (text[pos] == ' ' || text[pos] == '\t'))
            pos++;

        if (pos < len && text[pos] == '"') {
            quoted = 1;
            pos++;
            start = pos;
            while (pos < len) {
                if (text[pos] == '"') {
                    if (pos + 1 < len && text[pos + 1] == '"') {
                        pos += 2;
                        continue;
                    }
                    break;
                }
                pos++;
            }
            end = pos;
            if (pos < len)
                pos++;
            else
                bad++;
        } else {
            start = pos;
            while (pos < len && text[pos] != ',' && text[pos] != '\n' && text[pos] != '\r')
                pos++;
            end = pos;
            while (end > start && (text[end - 1] == ' ' || text[end - 1] == '\t'))
                end--;
        }

        isNumber = quoted ? 0 : 1;
        for (j = start; j < end && isNumber; j++) {
            char c = text[j];
            if (j == start && (c == '-' || c == '+')) {
                if (c == '-')
                    sign = -1;
                continue;
            }
            if (c < '0' || c > '9') {
                isNumber = 0;
                break;
            }
            number = number * 10 + (c - '0');
            digits++;
        }
        if (digits == 0)
            isNumber = 0;

        if (count < cap) {
            fields[count].start = start;
            fields[count].length = end - start;
            fields[count].isNumber = isNumber;
            fields[count].number = isNumber ? sign * number : 0;
            count++;
        } else {
            bad++;
        }
        atLineStart = 0;

        if (pos < len && text[pos] == ',') {
            pos++;
            continue;
        }

        rows++;
        atLineStart = 1;
        if (pos < len && text[pos] == '\r')
            pos++;
        if (pos < len && text[pos] == '\n')
            pos++;
        else if (pos >= len)
            break;
    }

    if (rowCount)
        *rowCount = rows;
    if (bad)
        return -(bad + 1);
    return count;
}

/* ------------------------------------------------------------------ */
/* 10. A fixed-step n-body integrator with a hand-rolled square root.   */

struct Body {
    double x, y;
    double vx, vy;
    double mass;
};

static double huge_sqrt(double v)
{
    double guess;
    int i;
    if (v <= 0.0)
        return 0.0;
    guess = v > 1.0 ? v * 0.5 : 1.0;
    for (i = 0; i < 24; i++) {
        double next = 0.5 * (guess + v / guess);
        double delta = next - guess;
        if (delta < 0.0)
            delta = -delta;
        guess = next;
        if (delta < 1e-12)
            break;
    }
    return guess;
}

API int physics_step(struct Body* bodies, int n, double dt, int steps, double* energyOut)
{
    int s, i, j;
    int collisions = 0;
    double softening = 1e-6;

    if (n <= 0 || n > 64 || steps <= 0)
        return -1;

    for (s = 0; s < steps; s++) {
        for (i = 0; i < n; i++) {
            double ax = 0.0;
            double ay = 0.0;
            for (j = 0; j < n; j++) {
                double dx, dy, distSq, dist, inv;
                if (j == i)
                    continue;
                dx = bodies[j].x - bodies[i].x;
                dy = bodies[j].y - bodies[i].y;
                distSq = dx * dx + dy * dy + softening;
                dist = huge_sqrt(distSq);
                if (dist < 1e-4) {
                    collisions++;
                    continue;
                }
                inv = bodies[j].mass / (distSq * dist);
                ax += dx * inv;
                ay += dy * inv;
            }
            bodies[i].vx += ax * dt;
            bodies[i].vy += ay * dt;
        }

        for (i = 0; i < n; i++) {
            bodies[i].x += bodies[i].vx * dt;
            bodies[i].y += bodies[i].vy * dt;
        }
    }

    if (energyOut) {
        double kinetic = 0.0;
        double potential = 0.0;
        for (i = 0; i < n; i++) {
            double v2 = bodies[i].vx * bodies[i].vx + bodies[i].vy * bodies[i].vy;
            kinetic += 0.5 * bodies[i].mass * v2;
            for (j = i + 1; j < n; j++) {
                double dx = bodies[j].x - bodies[i].x;
                double dy = bodies[j].y - bodies[i].y;
                double dist = huge_sqrt(dx * dx + dy * dy + softening);
                if (dist > 1e-9)
                    potential -= bodies[i].mass * bodies[j].mass / dist;
            }
        }
        energyOut[0] = kinetic;
        energyOut[1] = potential;
        energyOut[2] = kinetic + potential;
    }

    return collisions;
}
