Use clambc_test_compiler as your "compiler" when building cmake with the llvm test suite.  It won't be able to use all of the clambc.h stuff, but you can use it to run individual opt passes.

```sh
cmake -G "Unix Makefiles" .. \
    -D TEST_SUITE_COLLECT_CODE_SIZE=OFF \
    -D CMAKE_C_COMPILER=clambc_test_compiler
```
