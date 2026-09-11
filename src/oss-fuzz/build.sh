#!/bin/bash -eu
# Draft OSS-Fuzz build. Compile the three libFuzzer targets into $OUT.
# Expected cwd: the repository root ($SRC/libsigma).

cd src

python3 fuzz_corpus/gen_seed.py fuzz_corpus/load/seed.sigmac

$CC $CFLAGS -std=c11 -I. \
  fuzz_load.c sigma_match.c sigma_format.c \
  -lpcre2-8 $LIB_FUZZING_ENGINE -o $OUT/fuzz_load

$CC $CFLAGS -std=c11 -I. \
  fuzz_contrib.c contrib_wire.c \
  -ljson-c $LIB_FUZZING_ENGINE -o $OUT/fuzz_contrib

$CC $CFLAGS -std=c11 -I. \
  fuzz_match.c sigma_match.c sigma_format.c \
  -lpcre2-8 $LIB_FUZZING_ENGINE -o $OUT/fuzz_match

mkdir -p $OUT/fuzz_load_seed_corpus $OUT/fuzz_contrib_seed_corpus
cp fuzz_corpus/load/seed.sigmac $OUT/fuzz_load_seed_corpus/
cp fuzz_corpus/contrib/*.json $OUT/fuzz_contrib_seed_corpus/
# fuzz_match loads seed.sigmac from cwd at init; place it next to the binary.
cp fuzz_corpus/load/seed.sigmac $OUT/seed.sigmac
zip -q -j $OUT/fuzz_load_seed_corpus.zip $OUT/fuzz_load_seed_corpus/* || true
zip -q -j $OUT/fuzz_contrib_seed_corpus.zip $OUT/fuzz_contrib_seed_corpus/* || true
