# Target output quality

The reference the C backend is aiming at. Not perfect decompilation — the goal
is output a reader can follow and trust.

## Worked examples

```c
/* confidence: HIGH */
INT fnv1a_hash(BYTE* arg1, LONGLONG arg2) {
    BYTE* var2;

    if (arg2 == 0) {
        return FNV1A_OFFSET_32;
    }
    DWORD result = FNV1A_OFFSET_32;
    CHAR* var1 = (CHAR*)(arg2 + arg1);
    do {
        result = (result ^ *arg1) * 16777619;
        var2 = arg1;
        ++arg1;
    } while ((int64_t)(var1) != (int64_t)(var2 + 1));
    return result;
}

/* confidence: HIGH */
ULONGLONG gcd(ULONGLONG arg1, ULONGLONG arg2) {
    ULONGLONG var2;

    if (arg2 == 0) {
        return arg1;
    }
    do {
        const ULONGLONG var1 = arg1 / arg2;
        var2 = arg1 % arg2;
        arg1 = arg2;
        arg2 = var2;
    } while (var2 != 0);
    return arg1;
}

INT decode_packet(struct s_decode_packet_arg1* arg1, INT arg2, LONGLONG* arg3, LONGLONG* arg4) {
    if (arg2 <= 15) {
        return -1;
    }
    if (arg1->field_0 != DEADBEEF) {
        return -2;
    }
    ...
    BYTE* p = (BYTE*)(&arg1->field_10);
    do {
        var1 = var2 + *p;
        ++p;
        var2 = var1;
    } while ((int64_t)(p) != (int64_t)(var3));
    ...
}
```

## Requirements this implies

1. **Types** are Windows spellings: `void`, `bool`, `CHAR`, `BYTE`, `WORD`,
   `DWORD`, `INT`, `UINT`, `LONGLONG`, `ULONGLONG`, `float`, `double`,
   pointers, and named structs. Not `i32`/`u64`.
2. **Structs are recovered**, not left as opaque pointers: a pointer argument
   whose loads cluster at fixed offsets becomes
   `struct s_<function>_arg<N>*` with `field_<hexoffset>` members, including
   padding members marked `/* not accessed */`.
3. **Magic constants are named** where recognised: FNV offsets and primes,
   `0xDEADBEEF`, CRC polynomials, murmur/xoshiro constants.
4. **Variable naming**: `arg<N>` for parameters, `result` for the value that
   reaches `return`, `p` for pointers walked in a loop, `flag` for booleans,
   `var<N>` otherwise. `const` on locals assigned exactly once.
5. **Control flow** is structured: `if` / `else if` / `while` / `do while` /
   `for` / `switch` / `break` / `continue` / early `return`, and
   `while (true) { ... break; }` where that is the honest shape. `goto` only
   where a region is genuinely irreducible, and the count is reported.
6. **No machine registers** anywhere in the output, and no SSA artefacts: no
   `phi`, no one-variable-per-SSA-value, few temporaries.
7. **Casts only where the program really converts.** A cast that merely
   restates a type the reader can already see must not be printed.
8. **Confidence annotation** per function (`/* confidence: HIGH */`) derived
   from how much the analysis had to guess: unsupported instructions,
   unresolved indirect control flow, escaped frame memory, uncertain types.
