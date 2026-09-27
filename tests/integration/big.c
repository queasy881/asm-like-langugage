/* A corpus of larger, realistic functions. Each one is big enough to exercise
 * nested control flow, several live variables at once, struct access, and
 * mixed arithmetic - the things short test cases never reach. */

#include <stdint.h>

#ifdef DECOMP_EXPORT
#define API __declspec(dllexport)
#else
#define API
#endif

/* ------------------------------------------------------------------ */
/* 1. Arbitrary precision multiply, schoolbook with carry propagation.  */

API int bignum_mul(const uint32_t* a, int alen, const uint32_t* b, int blen, uint32_t* out, int outcap)
{
    int i, j;
    int used;

    if (alen <= 0 || blen <= 0 || outcap < alen + blen)
        return -1;

    for (i = 0; i < alen + blen; i++)
        out[i] = 0;

    for (i = 0; i < alen; i++) {
        uint64_t carry = 0;
        uint32_t ai = a[i];
        if (ai == 0)
            continue;
        for (j = 0; j < blen; j++) {
            uint64_t cur = (uint64_t)out[i + j];
            uint64_t prod = (uint64_t)ai * (uint64_t)b[j];
            uint64_t sum = cur + (prod & 0xFFFFFFFFu) + carry;
            out[i + j] = (uint32_t)sum;
            carry = (sum >> 32) + (prod >> 32);
        }
        {
            int k = i + blen;
            while (carry != 0 && k < outcap) {
                uint64_t sum = (uint64_t)out[k] + (carry & 0xFFFFFFFFu);
                out[k] = (uint32_t)sum;
                carry = (sum >> 32) + (carry >> 32);
                k++;
            }
            if (carry != 0)
                return -2;
        }
    }

    used = alen + blen;
    while (used > 1 && out[used - 1] == 0)
        used--;
    return used;
}

/* ------------------------------------------------------------------ */
/* 2. A tokenizer state machine over a byte buffer.                     */

#define TOK_END 0
#define TOK_NUM 1
#define TOK_STR 2
#define TOK_IDENT 3
#define TOK_PUNCT 4
#define TOK_ERROR 5

struct Token {
    int kind;
    int start;
    int length;
    int64_t value;
};

API int tokenize(const char* text, int len, struct Token* out, int maxTokens)
{
    int pos = 0;
    int count = 0;

    while (pos < len && count < maxTokens) {
        char c = text[pos];

        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            pos++;
            continue;
        }
        if (c == '/' && pos + 1 < len && text[pos + 1] == '/') {
            while (pos < len && text[pos] != '\n')
                pos++;
            continue;
        }

        out[count].start = pos;
        out[count].value = 0;

        if (c >= '0' && c <= '9') {
            int64_t v = 0;
            int base = 10;
            if (c == '0' && pos + 1 < len && (text[pos + 1] == 'x' || text[pos + 1] == 'X')) {
                base = 16;
                pos += 2;
            }
            while (pos < len) {
                int digit = -1;
                char d = text[pos];
                if (d >= '0' && d <= '9')
                    digit = d - '0';
                else if (base == 16 && d >= 'a' && d <= 'f')
                    digit = d - 'a' + 10;
                else if (base == 16 && d >= 'A' && d <= 'F')
                    digit = d - 'A' + 10;
                if (digit < 0 || digit >= base)
                    break;
                v = v * base + digit;
                pos++;
            }
            out[count].kind = TOK_NUM;
            out[count].value = v;
        } else if (c == '"') {
            int escaped = 0;
            pos++;
            while (pos < len) {
                char d = text[pos];
                if (escaped) {
                    escaped = 0;
                } else if (d == '\\') {
                    escaped = 1;
                } else if (d == '"') {
                    pos++;
                    break;
                }
                pos++;
            }
            out[count].kind = TOK_STR;
        } else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
            uint32_t hash = 2166136261u;
            while (pos < len) {
                char d = text[pos];
                int ok = (d >= 'a' && d <= 'z') || (d >= 'A' && d <= 'Z') || (d >= '0' && d <= '9') || d == '_';
                if (!ok)
                    break;
                hash = (hash ^ (unsigned char)d) * 16777619u;
                pos++;
            }
            out[count].kind = TOK_IDENT;
            out[count].value = hash;
        } else if (c == '+' || c == '-' || c == '*' || c == '/' || c == '(' || c == ')' ||
                   c == '{' || c == '}' || c == ';' || c == ',' || c == '=' || c == '<' || c == '>') {
            out[count].kind = TOK_PUNCT;
            out[count].value = c;
            pos++;
        } else {
            out[count].kind = TOK_ERROR;
            out[count].length = 1;
            return -(count + 1);
        }

        out[count].length = pos - out[count].start;
        count++;
    }
    if (count < maxTokens) {
        out[count].kind = TOK_END;
        out[count].start = pos;
        out[count].length = 0;
        out[count].value = 0;
    }
    return count;
}

/* ------------------------------------------------------------------ */
/* 3. CRC table construction and a checksum over it.                    */

API uint32_t crc32_with_table(const uint8_t* data, int len, uint32_t* table, int tableLen)
{
    int i, j;
    uint32_t crc;

    if (tableLen < 256)
        return 0;

    for (i = 0; i < 256; i++) {
        uint32_t c = (uint32_t)i;
        for (j = 0; j < 8; j++) {
            if (c & 1)
                c = 0xEDB88320u ^ (c >> 1);
            else
                c = c >> 1;
        }
        table[i] = c;
    }

    crc = 0xFFFFFFFFu;
    for (i = 0; i < len; i++) {
        uint8_t index = (uint8_t)((crc ^ data[i]) & 0xFF);
        crc = table[index] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

/* ------------------------------------------------------------------ */
/* 4. LU decomposition with partial pivoting, in doubles.               */

API int lu_decompose(double* m, int n, int* perm, int stride)
{
    int i, j, k;
    int sign = 1;

    if (n <= 0 || stride < n)
        return 0;

    for (i = 0; i < n; i++)
        perm[i] = i;

    for (k = 0; k < n; k++) {
        double best = 0.0;
        int pivot = -1;

        for (i = k; i < n; i++) {
            double v = m[i * stride + k];
            double av = v < 0.0 ? -v : v;
            if (av > best) {
                best = av;
                pivot = i;
            }
        }
        if (pivot < 0 || best < 1e-12)
            return 0;

        if (pivot != k) {
            int tmp = perm[k];
            perm[k] = perm[pivot];
            perm[pivot] = tmp;
            sign = -sign;
            for (j = 0; j < n; j++) {
                double t = m[k * stride + j];
                m[k * stride + j] = m[pivot * stride + j];
                m[pivot * stride + j] = t;
            }
        }

        {
            double diag = m[k * stride + k];
            for (i = k + 1; i < n; i++) {
                double factor = m[i * stride + k] / diag;
                m[i * stride + k] = factor;
                for (j = k + 1; j < n; j++)
                    m[i * stride + j] -= factor * m[k * stride + j];
            }
        }
    }
    return sign;
}

/* ------------------------------------------------------------------ */
/* 5. Heap sort, then a binary search over the result.                  */

static void sift_down(int* a, int start, int end)
{
    int root = start;
    while (root * 2 + 1 <= end) {
        int child = root * 2 + 1;
        int swap = root;
        if (a[swap] < a[child])
            swap = child;
        if (child + 1 <= end && a[swap] < a[child + 1])
            swap = child + 1;
        if (swap == root)
            return;
        {
            int t = a[root];
            a[root] = a[swap];
            a[swap] = t;
        }
        root = swap;
    }
}

API int heap_sort_search(int* a, int n, int needle)
{
    int start;
    int end;
    int lo, hi;

    if (n <= 0)
        return -1;

    for (start = (n - 2) / 2; start >= 0; start--)
        sift_down(a, start, n - 1);

    for (end = n - 1; end > 0; end--) {
        int t = a[0];
        a[0] = a[end];
        a[end] = t;
        sift_down(a, 0, end - 1);
    }

    lo = 0;
    hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        int v = a[mid];
        if (v == needle)
            return mid;
        if (v < needle)
            lo = mid + 1;
        else
            hi = mid - 1;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* 6. A routing table walk over a struct with several fields.           */

struct Route {
    uint32_t prefix;
    uint32_t mask;
    uint16_t metric;
    uint16_t flags;
    int32_t nextHop;
    int32_t iface;
};

API int route_lookup(const struct Route* table, int count, uint32_t address, int32_t* hopOut, int32_t* ifOut)
{
    int i;
    int best = -1;
    uint32_t bestMask = 0;
    uint16_t bestMetric = 0xFFFF;

    if (count <= 0)
        return -1;

    for (i = 0; i < count; i++) {
        const struct Route* r = &table[i];
        if ((r->flags & 1) == 0)
            continue;
        if ((address & r->mask) != (r->prefix & r->mask))
            continue;
        if (r->mask < bestMask)
            continue;
        if (r->mask == bestMask && r->metric >= bestMetric)
            continue;
        best = i;
        bestMask = r->mask;
        bestMetric = r->metric;
    }

    if (best < 0)
        return -1;
    if (hopOut)
        *hopOut = table[best].nextHop;
    if (ifOut)
        *ifOut = table[best].iface;
    if (table[best].flags & 2)
        return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* 7. UTF-8 decoding to code points, with validation.                   */

API int utf8_decode(const uint8_t* in, int inLen, uint32_t* out, int outCap)
{
    int i = 0;
    int n = 0;

    while (i < inLen && n < outCap) {
        uint8_t b0 = in[i];
        uint32_t cp;
        int extra;

        if (b0 < 0x80) {
            cp = b0;
            extra = 0;
        } else if ((b0 & 0xE0) == 0xC0) {
            cp = b0 & 0x1F;
            extra = 1;
        } else if ((b0 & 0xF0) == 0xE0) {
            cp = b0 & 0x0F;
            extra = 2;
        } else if ((b0 & 0xF8) == 0xF0) {
            cp = b0 & 0x07;
            extra = 3;
        } else {
            return -(i + 1);
        }

        if (i + extra >= inLen)
            return -(i + 1);

        {
            int k;
            for (k = 1; k <= extra; k++) {
                uint8_t bx = in[i + k];
                if ((bx & 0xC0) != 0x80)
                    return -(i + k + 1);
                cp = (cp << 6) | (uint32_t)(bx & 0x3F);
            }
        }

        if (extra == 1 && cp < 0x80)
            return -(i + 1);
        if (extra == 2 && cp < 0x800)
            return -(i + 1);
        if (extra == 3 && cp < 0x10000)
            return -(i + 1);
        if (cp >= 0xD800 && cp <= 0xDFFF)
            return -(i + 1);
        if (cp > 0x10FFFF)
            return -(i + 1);

        out[n] = cp;
        n++;
        i += extra + 1;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* 8. A free-list pool allocator over a caller supplied block.          */

struct PoolHeader {
    int32_t blockSize;
    int32_t blockCount;
    int32_t freeHead;
    int32_t liveCount;
    int32_t highWater;
    int32_t pad;
};

API int pool_init(void* memory, int totalBytes, int blockSize)
{
    struct PoolHeader* h;
    int usable;
    int count;
    int i;

    if (!memory || blockSize < 8 || totalBytes < (int)sizeof(struct PoolHeader) + blockSize)
        return -1;

    blockSize = (blockSize + 7) & ~7;
    h = (struct PoolHeader*)memory;
    usable = totalBytes - (int)sizeof(struct PoolHeader);
    count = usable / blockSize;
    if (count <= 0)
        return -1;

    h->blockSize = blockSize;
    h->blockCount = count;
    h->freeHead = 0;
    h->liveCount = 0;
    h->highWater = 0;
    h->pad = 0;

    for (i = 0; i < count; i++) {
        int32_t* slot = (int32_t*)((char*)memory + sizeof(struct PoolHeader) + (size_t)i * blockSize);
        *slot = (i + 1 < count) ? (i + 1) : -1;
    }
    return count;
}

API int pool_alloc(void* memory)
{
    struct PoolHeader* h = (struct PoolHeader*)memory;
    int index;
    int32_t* slot;

    if (!h || h->freeHead < 0)
        return -1;
    index = h->freeHead;
    slot = (int32_t*)((char*)memory + sizeof(struct PoolHeader) + (size_t)index * h->blockSize);
    h->freeHead = *slot;
    h->liveCount++;
    if (h->liveCount > h->highWater)
        h->highWater = h->liveCount;
    return index;
}

API int pool_free(void* memory, int index)
{
    struct PoolHeader* h = (struct PoolHeader*)memory;
    int32_t* slot;

    if (!h || index < 0 || index >= h->blockCount)
        return -1;
    slot = (int32_t*)((char*)memory + sizeof(struct PoolHeader) + (size_t)index * h->blockSize);
    *slot = h->freeHead;
    h->freeHead = index;
    h->liveCount--;
    return h->liveCount;
}

/* ------------------------------------------------------------------ */
/* 9. A bytecode interpreter with a wide opcode switch.                 */

struct VmState {
    int32_t stack[64];
    int32_t sp;
    int32_t pc;
    int32_t regs[8];
    int32_t flags;
    int32_t steps;
};

API int vm_run(struct VmState* vm, const uint8_t* code, int codeLen, int maxSteps)
{
    vm->sp = 0;
    vm->pc = 0;
    vm->steps = 0;
    vm->flags = 0;

    while (vm->steps < maxSteps && vm->pc < codeLen) {
        uint8_t op = code[vm->pc];
        int32_t a = (vm->pc + 1 < codeLen) ? (int32_t)(int8_t)code[vm->pc + 1] : 0;
        int advance = 1;

        vm->steps++;

        switch (op) {
        case 0:
            return vm->sp > 0 ? vm->stack[vm->sp - 1] : 0;
        case 1:
            if (vm->sp >= 64)
                return -1;
            vm->stack[vm->sp++] = a;
            advance = 2;
            break;
        case 2:
            if (vm->sp < 1)
                return -2;
            vm->sp--;
            break;
        case 3:
            if (vm->sp < 2)
                return -2;
            vm->stack[vm->sp - 2] += vm->stack[vm->sp - 1];
            vm->sp--;
            break;
        case 4:
            if (vm->sp < 2)
                return -2;
            vm->stack[vm->sp - 2] -= vm->stack[vm->sp - 1];
            vm->sp--;
            break;
        case 5:
            if (vm->sp < 2)
                return -2;
            vm->stack[vm->sp - 2] *= vm->stack[vm->sp - 1];
            vm->sp--;
            break;
        case 6:
            if (vm->sp < 2)
                return -2;
            if (vm->stack[vm->sp - 1] == 0)
                return -3;
            vm->stack[vm->sp - 2] /= vm->stack[vm->sp - 1];
            vm->sp--;
            break;
        case 7:
            if (vm->sp < 1 || a < 0 || a >= 8)
                return -4;
            vm->regs[a] = vm->stack[--vm->sp];
            advance = 2;
            break;
        case 8:
            if (vm->sp >= 64 || a < 0 || a >= 8)
                return -4;
            vm->stack[vm->sp++] = vm->regs[a];
            advance = 2;
            break;
        case 9:
            if (vm->sp < 2)
                return -2;
            vm->flags = vm->stack[vm->sp - 2] - vm->stack[vm->sp - 1];
            vm->sp -= 2;
            break;
        case 10:
            if (vm->flags == 0)
                vm->pc += a;
            advance = 2;
            break;
        case 11:
            if (vm->flags != 0)
                vm->pc += a;
            advance = 2;
            break;
        case 12:
            vm->pc += a;
            advance = 2;
            break;
        case 13:
            if (vm->sp < 1)
                return -2;
            vm->stack[vm->sp - 1] = -vm->stack[vm->sp - 1];
            break;
        case 14:
            if (vm->sp < 2)
                return -2;
            {
                int32_t t = vm->stack[vm->sp - 1];
                vm->stack[vm->sp - 1] = vm->stack[vm->sp - 2];
                vm->stack[vm->sp - 2] = t;
            }
            break;
        case 15:
            if (vm->sp < 1 || vm->sp >= 64)
                return -2;
            vm->stack[vm->sp] = vm->stack[vm->sp - 1];
            vm->sp++;
            break;
        default:
            return -5;
        }
        vm->pc += advance;
    }
    return vm->sp > 0 ? vm->stack[vm->sp - 1] : 0;
}

/* ------------------------------------------------------------------ */
/* 10. Greedy word wrapping with lookahead and hyphenation.             */

API int text_wrap(const char* text, int len, int width, int* breaks, int maxBreaks)
{
    int i = 0;
    int lineStart = 0;
    int lastSpace = -1;
    int count = 0;

    if (width <= 0)
        return -1;

    while (i < len) {
        char c = text[i];

        if (c == '\n') {
            if (count >= maxBreaks)
                return -2;
            breaks[count++] = i;
            lineStart = i + 1;
            lastSpace = -1;
            i++;
            continue;
        }
        if (c == ' ' || c == '\t')
            lastSpace = i;

        if (i - lineStart >= width) {
            int breakAt;
            if (lastSpace > lineStart) {
                breakAt = lastSpace;
            } else {
                int j = i;
                while (j > lineStart && text[j] != '-')
                    j--;
                breakAt = (j > lineStart) ? j : i;
            }
            if (count >= maxBreaks)
                return -2;
            breaks[count++] = breakAt;
            lineStart = breakAt + 1;
            lastSpace = -1;
            i = breakAt + 1;
            continue;
        }
        i++;
    }
    if (count < maxBreaks && lineStart < len)
        breaks[count++] = len;
    return count;
}
