# Integration corpus

`cases.c` is compiled three ways:

* natively into the test binary, giving the reference results
* with `x86_64-w64-mingw32-gcc` into a 64-bit PE
* with `i686-w64-mingw32-gcc` into a 32-bit PE

The test decompiles each exported function from both PEs, runs the recovered
IR in the interpreter, and checks the result against the native run. Pointer
arguments get a scratch buffer whose contents are compared afterwards, so
stores are checked too.
