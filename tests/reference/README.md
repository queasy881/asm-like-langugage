# Reference output

`behemoth_reference.c` is a high-quality decompilation of the exports in
`tests/corpus/behemoth.dll`, supplied as the quality bar for this project. It
is *not* ground truth for correctness - `tests/unit/test_opt.cpp` and
`tests/unit/test_integration.cpp` establish that against real execution. It is
the bar for **readability**: struct recovery, naming, loop shape, casts and
comments.

Use `tools/compare_reference.sh` to diff our output against it per function.

Notable things the reference does that are worth matching:

* Recovers a named struct per pointer parameter (`s_decode_packet_arg1`) and a
  hash-named one for anonymous shapes (`s_shape_81eed7f4`), with unaccessed
  padding members spelled out and `#pragma pack(push, 1)` around them.
* Names fields semantically where it can: `count`, `flag`, `next`.
* Names magic constants: `FNV1A_OFFSET_32`, `FNV1A_PRIME_64`, `DEADBEEF`.
* Names variables by role: `p`/`q` for walked pointers, `i`/`count` for
  induction variables, `total`/`result` for accumulators, `flag` for booleans.
* Prefers `do { } while (c)` over `while (true) { ... if (c) break; }`.
* Emits compiler intrinsics by name: `_rotl`, `_rotr64`, `_byteswap_ulong`,
  `__umulh`, with portable fallback definitions when they are used.
* Annotates each function with its frame layout, loop count, callees, and a
  confidence that drops when a goto survives.
* Is explicitly not perfect: `tree_search` below contains a wrong
  `1 ? a : b`, which is a reminder that the bar is "very good", not "exact".
