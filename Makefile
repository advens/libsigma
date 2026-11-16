# libsigma: compiled Sigma selection matcher + in-process correlator.
#
#   make           shared + static library + sigma_cli
#   make test      matcher, SIMD, correlation, event_time, wire
#   make san       ASan + UBSan over the SIMD oracle and the engine
#   make tsan      correlation TSan
#   make cli       sigma_cli only
#   make bench     corpus throughput harness (bench_corpus)
#   make bench-simd  CONTAINS-heavy microbench (bench_sigma)
#   make conformance reference emitter -> C loader/matcher, byte parity
#   make libfuzz   libFuzzer load/match/contrib
#   make libfuzz-ci  libFuzzer CI smoke (45s each, ASan+UBSan)
#   make diffuzz   C matcher vs an external reference evaluator (needs SIGMAC_SRC)
#   make test-events JSON front end (sigma_events) against the conformance artifact
#   make wasm      wasm32-wasip1 library, sigma_cli.wasm, libsigma.wasm module (git tree only)
#   make wasm-test engine tests, test_events, conformance, and the NEON golden under wasmtime
#   make install   PREFIX (default /usr/local)
#   make clean

PREFIX     ?= /usr/local
DESTDIR    ?=
LIB_MAJOR  := 4
LIB_MINOR  := 0
LIB_PATCH  := 2
SONAME     := libsigma.so.$(LIB_MAJOR)
SOFILE     := libsigma.so.$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)

CC         ?= cc
AR         ?= ar
CSTD       := -std=c11
WARN       := -Wall -Wextra -Wpedantic
HARDEN     := -fstack-protector-strong -D_FORTIFY_SOURCE=2
OPT        := -O2
PCRE2_CFLAGS ?= $(shell pkg-config --cflags libpcre2-8 2>/dev/null)
PCRE2_LIBS   ?= $(shell pkg-config --libs libpcre2-8 2>/dev/null || echo -lpcre2-8)
JSON_CFLAGS  ?= $(shell pkg-config --cflags libfastjson 2>/dev/null || pkg-config --cflags json-c 2>/dev/null)
JSON_LIBS    ?= $(shell pkg-config --libs libfastjson 2>/dev/null || pkg-config --libs json-c 2>/dev/null || echo -ljson-c)
# The JSON package the build actually resolved, for sigma.pc Requires.private.
JSON_PC      ?= $(shell pkg-config --exists libfastjson 2>/dev/null && echo libfastjson || echo json-c)

ARCH := $(shell uname -m)
ifeq ($(ARCH),arm64)
    ARCHFLAGS := -march=armv8-a+crc
else ifeq ($(ARCH),aarch64)
    ARCHFLAGS := -march=armv8-a+crc
else ifeq ($(ARCH),x86_64)
    ARCHFLAGS := -march=x86-64-v2 -msse4.2
else ifeq ($(ARCH),amd64)
    ARCHFLAGS := -march=x86-64-v2 -msse4.2
else
    ARCHFLAGS :=
endif

OS := $(shell uname -s)
ifeq ($(OS),FreeBSD)
    PCDIR := $(PREFIX)/libdata/pkgconfig
    THREAD_LIBS := -lpthread
    SHLIB := $(SOFILE)
    SHLIB_SONAME := $(SONAME)
    SHLIB_LINK := libsigma.so
else ifeq ($(OS),Darwin)
    PCDIR := $(PREFIX)/lib/pkgconfig
    THREAD_LIBS :=
    SHLIB := libsigma.$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH).dylib
    SHLIB_SONAME := libsigma.$(LIB_MAJOR).dylib
    SHLIB_LINK := libsigma.dylib
else
    PCDIR := $(PREFIX)/lib/pkgconfig
    THREAD_LIBS := -lpthread
    CSTD += -D_POSIX_C_SOURCE=200809L
    SHLIB := $(SOFILE)
    SHLIB_SONAME := $(SONAME)
    SHLIB_LINK := libsigma.so
endif

CFLAGS := $(CSTD) $(WARN) $(HARDEN) $(OPT) $(ARCHFLAGS) -fPIC -pthread \
          $(PCRE2_CFLAGS) $(JSON_CFLAGS)
ifeq ($(SCALAR),1)
CFLAGS += -DSIGMA_FORCE_SCALAR
endif
LIBS   := $(PCRE2_LIBS) $(JSON_LIBS) $(THREAD_LIBS) -lm

SRCDIR   := src
BUILDDIR := build
LIB_SRCS := $(SRCDIR)/sigma_match.c $(SRCDIR)/sigma_format.c \
            $(SRCDIR)/classify_corr.c $(SRCDIR)/corr_format.c \
            $(SRCDIR)/contrib_wire.c $(SRCDIR)/event_time.c
LIB_OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(LIB_SRCS))
HEADERS  := $(SRCDIR)/sigma_match.h $(SRCDIR)/sigma_format.h \
            $(SRCDIR)/classify_corr.h $(SRCDIR)/corr_format.h \
            $(SRCDIR)/contrib_wire.h $(SRCDIR)/event_time.h

FUZZ_CC   ?= $(shell if test -x /opt/homebrew/opt/llvm/bin/clang; then \
		echo /opt/homebrew/opt/llvm/bin/clang; \
		elif command -v clang >/dev/null 2>&1; then command -v clang; \
		else echo $(CC); fi)
FUZZ_RUNS ?= 20000
FUZZ_MAXLEN ?= 8192
# -detect_leaks=0: LSan reports json-c parse trees from the uninstrumented
# dylib as leaked even after json_object_put (fuzz_contrib.c cannot be
# patched in this change). ASan/UBSan still abort on overflow, UAF, UB.
FUZZ_CI_FLAGS := -max_total_time=45 -rss_limit_mb=2048 -timeout=25 -detect_leaks=0
# fuzz_contrib.c uses json-c names (json_tokener_get_error). Prefer json-c
# over libfastjson so the fuzzer builds on Darwin Homebrew and Linux CI.
FUZZ_JSON_CFLAGS ?= $(shell pkg-config --cflags json-c 2>/dev/null || echo $(JSON_CFLAGS))
FUZZ_JSON_LIBS   ?= $(shell pkg-config --libs json-c 2>/dev/null || echo $(JSON_LIBS))

# The `.sigmac` emitters (gen_seed.py, conformance_emit.py) use the bundled
# reference package in src/reference/ and need nothing set. SIGMAC_SRC, when
# set, points at an external `sigmac` package and is REQUIRED only by `diffuzz`
# (which also needs that package's YAML compiler + evaluator).
SIGMAC_SRC ?=
SIGMAC_PY  ?= python3

.PHONY: all test san tsan cli bench bench-simd fuzz libfuzz libfuzz-ci diffuzz diffuzz-arch diffuzz-c-arch conformance test-events wasm wasm-deps wasm-test install clean

all: $(BUILDDIR)/$(SHLIB) $(BUILDDIR)/libsigma.a $(BUILDDIR)/sigma_cli sigma.pc

sigma.pc: sigma.pc.in
	sed -e 's|@PREFIX@|$(PREFIX)|g' \
	    -e 's|@VERSION@|$(LIB_MAJOR).$(LIB_MINOR).$(LIB_PATCH)|g' \
	    -e 's|@JSON_DEP@|$(JSON_PC)|g' \
	    sigma.pc.in > sigma.pc

$(BUILDDIR):
	@mkdir -p $(BUILDDIR)

# -MMD -MP so a header edit rebuilds the objects that include it; without it a
# change to sigma_teddy.h / sigma_simd.h silently kept a stale sigma_match.o.
$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(LIB_OBJS:.o=.d)

$(BUILDDIR)/$(SHLIB): $(LIB_OBJS)
ifeq ($(OS),Darwin)
	$(CC) -dynamiclib -install_name $(SHLIB_SONAME) -o $@ $(LIB_OBJS) $(LIBS)
	ln -sf $(SHLIB) $(BUILDDIR)/$(SHLIB_SONAME)
	ln -sf $(SHLIB) $(BUILDDIR)/$(SHLIB_LINK)
else
	$(CC) -shared -Wl,-soname,$(SHLIB_SONAME) -pthread -o $@ $(LIB_OBJS) $(LIBS)
	ln -sf $(SHLIB) $(BUILDDIR)/$(SHLIB_SONAME)
	ln -sf $(SHLIB) $(BUILDDIR)/$(SHLIB_LINK)
endif

$(BUILDDIR)/libsigma.a: $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

$(BUILDDIR)/sigma_cli: $(SRCDIR)/sigma_cli.c $(BUILDDIR)/libsigma.a $(wildcard $(SRCDIR)/*.h)
	$(CC) $(CFLAGS) -o $@ $(SRCDIR)/sigma_cli.c $(BUILDDIR)/libsigma.a $(LIBS)

# One-shot scalar binary (same sources, no SIMD). Used to prove native ==
# scalar hitsets on this host; amd64 CI uses SCALAR=0 native = SSE4.2.
$(BUILDDIR)/sigma_cli_scalar: $(SRCDIR)/sigma_cli.c $(wildcard $(SRCDIR)/*.h) | $(BUILDDIR)
	$(CC) $(CSTD) $(WARN) $(HARDEN) $(OPT) -DSIGMA_FORCE_SCALAR -fPIC -pthread \
		$(PCRE2_CFLAGS) $(JSON_CFLAGS) -o $@ \
		$(SRCDIR)/sigma_cli.c $(SRCDIR)/sigma_match.c $(SRCDIR)/sigma_format.c \
		$(SRCDIR)/classify_corr.c $(SRCDIR)/corr_format.c \
		$(SRCDIR)/contrib_wire.c $(SRCDIR)/event_time.c $(LIBS)

$(BUILDDIR)/test_sigma_match: $(SRCDIR)/test_sigma_match.c $(BUILDDIR)/libsigma.a $(wildcard $(SRCDIR)/*.h)
	$(CC) $(CFLAGS) -o $@ $(SRCDIR)/test_sigma_match.c $(BUILDDIR)/libsigma.a $(LIBS)

$(BUILDDIR)/test_classify: $(SRCDIR)/test_classify.c $(BUILDDIR)/libsigma.a $(wildcard $(SRCDIR)/*.h)
	$(CC) $(CFLAGS) -pthread -o $@ $(SRCDIR)/test_classify.c $(BUILDDIR)/libsigma.a $(LIBS)

$(BUILDDIR)/test_event_time: $(SRCDIR)/test_event_time.c $(BUILDDIR)/libsigma.a $(wildcard $(SRCDIR)/*.h)
	$(CC) $(CFLAGS) -o $@ $(SRCDIR)/test_event_time.c $(BUILDDIR)/libsigma.a $(LIBS)

$(BUILDDIR)/test_wire: $(SRCDIR)/test_wire.c $(BUILDDIR)/libsigma.a $(wildcard $(SRCDIR)/*.h)
	$(CC) $(CFLAGS) -o $@ $(SRCDIR)/test_wire.c $(BUILDDIR)/libsigma.a $(LIBS)

$(BUILDDIR)/fuzz_simd: $(SRCDIR)/fuzz_simd.c $(wildcard $(SRCDIR)/*.h) | $(BUILDDIR)
	$(CC) $(CSTD) $(WARN) $(OPT) $(ARCHFLAGS) -o $@ $(SRCDIR)/fuzz_simd.c

$(BUILDDIR)/bench_corpus: $(SRCDIR)/bench_corpus.c $(BUILDDIR)/libsigma.a $(wildcard $(SRCDIR)/*.h)
	$(CC) $(CFLAGS) -O3 -o $@ $(SRCDIR)/bench_corpus.c $(BUILDDIR)/libsigma.a $(LIBS)

$(BUILDDIR)/bench_sigma: $(SRCDIR)/bench_sigma.c $(BUILDDIR)/libsigma.a $(wildcard $(SRCDIR)/*.h)
	$(CC) $(CFLAGS) -O3 -o $@ $(SRCDIR)/bench_sigma.c $(BUILDDIR)/libsigma.a $(LIBS)

cli: $(BUILDDIR)/sigma_cli

bench: $(BUILDDIR)/bench_corpus

bench-simd: $(BUILDDIR)/bench_sigma
	$(BUILDDIR)/bench_sigma

test: $(BUILDDIR)/test_sigma_match $(BUILDDIR)/fuzz_simd \
      $(BUILDDIR)/test_classify $(BUILDDIR)/test_event_time \
      $(BUILDDIR)/test_wire
	$(BUILDDIR)/test_sigma_match
	$(BUILDDIR)/fuzz_simd
	$(BUILDDIR)/test_classify
	$(BUILDDIR)/test_event_time
	$(BUILDDIR)/test_wire

# The library sources are compiled into each sanitizer binary, not linked
# from libsigma.a: an uninstrumented archive hides reads inside the library.
san: $(BUILDDIR)/fuzz_simd
	$(CC) $(CSTD) $(WARN) -O1 -g $(ARCHFLAGS) -fsanitize=address,undefined \
		-o $(BUILDDIR)/fuzz_simd_san $(SRCDIR)/fuzz_simd.c
	$(BUILDDIR)/fuzz_simd_san
	$(CC) $(CFLAGS) -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -pthread \
		-o $(BUILDDIR)/test_classify_san $(SRCDIR)/test_classify.c \
		$(LIB_SRCS) $(LIBS)
	$(BUILDDIR)/test_classify_san
	$(CC) $(CFLAGS) -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -pthread \
		-o $(BUILDDIR)/test_event_time_san $(SRCDIR)/test_event_time.c \
		$(LIB_SRCS) $(LIBS)
	$(BUILDDIR)/test_event_time_san
	$(CC) $(CFLAGS) -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -pthread \
		-o $(BUILDDIR)/test_wire_san $(SRCDIR)/test_wire.c \
		$(LIB_SRCS) $(LIBS)
	$(BUILDDIR)/test_wire_san

# Correlator only: libc + pthread + -lm, so this gate needs neither PCRE2
# nor a JSON library on the runner.
tsan: $(BUILDDIR)
	$(CC) $(CSTD) $(WARN) -O1 -g -fsanitize=thread -pthread \
		-o $(BUILDDIR)/test_classify_tsan $(SRCDIR)/test_classify.c \
		$(SRCDIR)/classify_corr.c -lm
	$(BUILDDIR)/test_classify_tsan
	$(CC) $(CSTD) $(WARN) -O1 -g -fsanitize=thread -pthread \
		-o $(BUILDDIR)/test_corr_concurrency_tsan \
		$(SRCDIR)/test_corr_concurrency.c $(SRCDIR)/classify_corr.c -lm
	$(BUILDDIR)/test_corr_concurrency_tsan

fuzz: test san

$(BUILDDIR)/seed.sigmac: $(SRCDIR)/fuzz_corpus/gen_seed.py | $(BUILDDIR)
	@mkdir -p $(SRCDIR)/fuzz_corpus/load
	SIGMAC_SRC=$(SIGMAC_SRC) $(SIGMAC_PY) $(SRCDIR)/fuzz_corpus/gen_seed.py \
		$(SRCDIR)/fuzz_corpus/load/seed.sigmac
	@cp $(SRCDIR)/fuzz_corpus/load/seed.sigmac $(BUILDDIR)/seed.sigmac

libfuzz: $(BUILDDIR) $(BUILDDIR)/seed.sigmac $(BUILDDIR)/libsigma.a
	@echo "--- libFuzzer (CC=$(FUZZ_CC) runs=$(FUZZ_RUNS)) ---"
	$(FUZZ_CC) -std=c11 $(WARN) -O1 -g -fsanitize=fuzzer,address,undefined \
		$(PCRE2_CFLAGS) $(SRCDIR)/fuzz_load.c $(SRCDIR)/sigma_match.c \
		$(SRCDIR)/sigma_format.c $(PCRE2_LIBS) -o $(BUILDDIR)/fuzz_load
	$(FUZZ_CC) -std=c11 $(WARN) -O1 -g -fsanitize=fuzzer,address,undefined \
		$(PCRE2_CFLAGS) $(SRCDIR)/fuzz_match.c $(SRCDIR)/sigma_match.c \
		$(SRCDIR)/sigma_format.c $(PCRE2_LIBS) -o $(BUILDDIR)/fuzz_match
	$(FUZZ_CC) -std=c11 $(WARN) -O1 -g -fsanitize=fuzzer,address,undefined \
		$(FUZZ_JSON_CFLAGS) $(SRCDIR)/fuzz_contrib.c $(SRCDIR)/contrib_wire.c \
		$(FUZZ_JSON_LIBS) -o $(BUILDDIR)/fuzz_contrib
	$(BUILDDIR)/fuzz_load -runs=$(FUZZ_RUNS) -max_len=$(FUZZ_MAXLEN) \
		-timeout=2 $(SRCDIR)/fuzz_corpus/load
	$(BUILDDIR)/fuzz_match -runs=$(FUZZ_RUNS) -max_len=$(FUZZ_MAXLEN) \
		-timeout=2
	$(BUILDDIR)/fuzz_contrib -runs=$(FUZZ_RUNS) -max_len=$(FUZZ_MAXLEN) \
		-timeout=2 $(SRCDIR)/fuzz_corpus/contrib
	@echo "libFuzzer: $(FUZZ_RUNS) runs x 3 targets OK"

# Bounded libFuzzer smoke for GitLab. Wall clock 45s per libFuzzer target so
# the parent validate stage stays a gate, not a campaign. fuzz_simd is the
# deterministic SIMD oracle (not a libFuzzer harness); it runs under ASan+UBSan.
# Load seed (gen_seed.py) is optional: committed contrib JSON is the corpus.
libfuzz-ci: $(BUILDDIR)
	@echo "--- libFuzzer CI (CC=$(FUZZ_CC) $(FUZZ_CI_FLAGS)) ---"
	@mkdir -p $(SRCDIR)/fuzz_corpus/load
	-@SIGMAC_SRC=$(SIGMAC_SRC) $(SIGMAC_PY) $(SRCDIR)/fuzz_corpus/gen_seed.py \
		$(SRCDIR)/fuzz_corpus/load/seed.sigmac >/dev/null 2>&1
	$(FUZZ_CC) -std=c11 $(WARN) -O1 -g -fsanitize=fuzzer,address,undefined \
		$(PCRE2_CFLAGS) $(SRCDIR)/fuzz_load.c $(SRCDIR)/sigma_match.c \
		$(SRCDIR)/sigma_format.c $(PCRE2_LIBS) -o $(BUILDDIR)/fuzz_load
	$(FUZZ_CC) -std=c11 $(WARN) -O1 -g -fsanitize=fuzzer,address,undefined \
		$(PCRE2_CFLAGS) $(SRCDIR)/fuzz_match.c $(SRCDIR)/sigma_match.c \
		$(SRCDIR)/sigma_format.c $(PCRE2_LIBS) -o $(BUILDDIR)/fuzz_match
	$(FUZZ_CC) $(CSTD) $(WARN) -O1 -g $(ARCHFLAGS) -fsanitize=address,undefined \
		-o $(BUILDDIR)/fuzz_simd_san $(SRCDIR)/fuzz_simd.c
	@rm -rf $(BUILDDIR)/corpus_load $(BUILDDIR)/corpus_contrib $(BUILDDIR)/corpus_match
	@mkdir -p $(BUILDDIR)/corpus_load $(BUILDDIR)/corpus_contrib $(BUILDDIR)/corpus_match
	@if test -f $(SRCDIR)/fuzz_corpus/load/seed.sigmac; then \
		cp $(SRCDIR)/fuzz_corpus/load/seed.sigmac $(BUILDDIR)/corpus_load/; \
	fi
	@cp $(SRCDIR)/fuzz_corpus/contrib/*.json $(BUILDDIR)/corpus_contrib/
	ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	$(BUILDDIR)/fuzz_load $(FUZZ_CI_FLAGS) $(BUILDDIR)/corpus_load
	cd $(SRCDIR) && ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	../$(BUILDDIR)/fuzz_match $(FUZZ_CI_FLAGS) ../$(BUILDDIR)/corpus_match
	@if $(FUZZ_CC) -std=c11 $(WARN) -O1 -g -fsanitize=fuzzer,address,undefined \
		$(FUZZ_JSON_CFLAGS) $(SRCDIR)/fuzz_contrib.c $(SRCDIR)/contrib_wire.c \
		$(FUZZ_JSON_LIBS) -o $(BUILDDIR)/fuzz_contrib; then \
		ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(BUILDDIR)/fuzz_contrib $(FUZZ_CI_FLAGS) $(BUILDDIR)/corpus_contrib; \
	else \
		echo "skip fuzz_contrib: json.h not available on this runner"; \
	fi
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	$(BUILDDIR)/fuzz_simd_san
	@echo "libFuzzer CI: load/match/contrib + fuzz_simd OK"

diffuzz: cli
	SIGMAC_SRC=$(SIGMAC_SRC) $(SIGMAC_PY) $(SRCDIR)/fuzz_diff.py --seed 1

# Native (NEON or SSE4.2) vs scalar: same seed, identical matcher + corr dumps.
diffuzz-arch: $(BUILDDIR)/sigma_cli $(BUILDDIR)/sigma_cli_scalar
	@mkdir -p $(BUILDDIR)
	SIGMAC_SRC=$(SIGMAC_SRC) SIGMA_CLI=$(BUILDDIR)/sigma_cli \
		$(SIGMAC_PY) $(SRCDIR)/fuzz_diff.py --seed 1 --dump $(BUILDDIR)/dump-native.txt
	SIGMAC_SRC=$(SIGMAC_SRC) SIGMA_CLI=$(BUILDDIR)/sigma_cli_scalar \
		$(SIGMAC_PY) $(SRCDIR)/fuzz_diff.py --seed 1 --dump $(BUILDDIR)/dump-scalar.txt
	diff -u $(BUILDDIR)/dump-native.txt $(BUILDDIR)/dump-scalar.txt
	@echo "diffuzz-arch: native == scalar (matcher + correlation fires)"
	@if test -f $(SRCDIR)/fuzz_corpus/dump-seed1.txt; then \
		diff -u $(SRCDIR)/fuzz_corpus/dump-seed1.txt $(BUILDDIR)/dump-native.txt; \
		echo "diffuzz-arch: native == committed NEON golden dump"; \
	fi

# C-only arch gate: no Python. Replay a committed .sigmac + corr JSON + TSV
# (compiled on NEON) with native SIMD vs scalar. Used by linux_amd64 CI
# (SSE4.2) which has no pip/pysigma.
ARCH_FIX := $(SRCDIR)/fuzz_corpus/arch
diffuzz-c-arch: $(BUILDDIR)/sigma_cli $(BUILDDIR)/sigma_cli_scalar
	$(BUILDDIR)/sigma_cli $(ARCH_FIX)/arch.sigmac $(ARCH_FIX)/arch.corr.json \
		< $(ARCH_FIX)/arch.tsv > $(BUILDDIR)/arch-native.txt
	$(BUILDDIR)/sigma_cli_scalar $(ARCH_FIX)/arch.sigmac $(ARCH_FIX)/arch.corr.json \
		< $(ARCH_FIX)/arch.tsv > $(BUILDDIR)/arch-scalar.txt
	diff -u $(BUILDDIR)/arch-native.txt $(BUILDDIR)/arch-scalar.txt
	diff -u $(ARCH_FIX)/arch.dump $(BUILDDIR)/arch-native.txt
	@echo "diffuzz-c-arch: native == scalar == NEON golden (matcher + corr)"

# sigma_events.c is the JSON front end the wasm module exports. It is not in
# LIB_SRCS: the native library does not change. The test compiles it in.
$(BUILDDIR)/test_events: $(SRCDIR)/test_events.c $(SRCDIR)/sigma_events.c $(BUILDDIR)/libsigma.a $(wildcard $(SRCDIR)/*.h)
	$(CC) $(CFLAGS) -o $@ $(SRCDIR)/test_events.c $(SRCDIR)/sigma_events.c $(BUILDDIR)/libsigma.a $(LIBS)

test-events: $(BUILDDIR)/test_events
	@SIGMAC_SRC=$(SIGMAC_SRC) $(SIGMAC_PY) $(SRCDIR)/conformance_emit.py $(BUILDDIR)/conf.sigmac
	$(BUILDDIR)/test_events $(BUILDDIR)/conf.sigmac $(ARCH_FIX)/arch.sigmac $(ARCH_FIX)/arch.corr.json

# One event per conformance rule. Native and wasm check the same lines and ids.
CONF_EVENTS := process.command_line=powershell -enc ZZ\nprocess.name=C:\\tools\\MiMiKatz.exe\ndestination.port=8443\nsource.ip=10.5.6.7\nnetwork.info=connect to port 443 now\nuser.name=alice\tuser.target=alice\n
CONF_RULES  := 100 200 300 600 700 800

conformance: cli
	@SIGMAC_SRC=$(SIGMAC_SRC) $(SIGMAC_PY) $(SRCDIR)/conformance_emit.py $(BUILDDIR)/conf.sigmac
	@printf '$(CONF_EVENTS)' > $(BUILDDIR)/conf_ev.tsv
	@out=$$($(BUILDDIR)/sigma_cli $(BUILDDIR)/conf.sigmac < $(BUILDDIR)/conf_ev.tsv); echo "$$out"; \
	 for r in $(CONF_RULES); do echo "$$out" | grep -q "rule=$$r" || { echo "CONFORMANCE FAIL: rule $$r did not fire"; exit 1; }; done; \
	 echo "CONFORMANCE OK: Python-emitted .sigmac loaded + matched by C sigma_cli (6/6 rules incl. fieldref)"

# ---------------------------------------------------------------------------
# wasm32-wasip1. Built from the git tree only: scripts/ is not in the release
# tarball. Nothing here is a prerequisite of all, test, or install, and none
# of these objects go into the native libsigma.
#
# WASM_DEPS, WASI_SDK, and WASMTIME can point at an existing tree.
WASM_DIR    := $(BUILDDIR)/wasm
WASM_DEPS   ?= $(WASM_DIR)/deps
WASI_SDK    ?= $(WASM_DEPS)/wasi-sdk
WASMTIME    ?= $(WASM_DEPS)/wasmtime/wasmtime
WASM_PINS   := $(WASM_DEPS)/.pins
WASM_CC     := $(WASI_SDK)/bin/clang --target=wasm32-wasip1 --sysroot=$(WASI_SDK)/share/wasi-sysroot
WASM_AR     := $(WASI_SDK)/bin/llvm-ar
# HARDEN is not applied: the stack protector and FORTIFY have no wasm32
# implementation. The module sandbox bounds every access to linear memory;
# ASan and UBSan cover the code inside it.
WASM_CFLAGS := -std=c11 -D_POSIX_C_SOURCE=200809L $(WARN) $(OPT) \
               -I$(WASM_DEPS)/include -I$(WASM_DEPS)/include/libfastjson
# --no-wasm-opt: clang otherwise runs any wasm-opt found in PATH, and the
# bytes would depend on the host. 1 MiB stack, 256 MiB memory ceiling.
WASM_LDFLAGS := --no-wasm-opt -Wl,-z,stack-size=1048576 -Wl,--max-memory=268435456
WASM_LIBS   := $(WASM_DEPS)/lib/libpcre2-8.a $(WASM_DEPS)/lib/libfastjson.a -lm
WASM_OBJS   := $(patsubst $(SRCDIR)/%.c,$(WASM_DIR)/obj/%.o,$(LIB_SRCS))
WASM_TESTS  := test_sigma_match test_classify test_event_time test_wire
# wasmtime sees src/ (fixtures) and build/ (generated artifacts) at the
# same relative paths the native targets use.
WASM_RUN    = $(WASMTIME) run --dir $(SRCDIR)::$(SRCDIR) --dir $(BUILDDIR)::$(BUILDDIR)

# The script exits at once when <deps>/.pins matches its pins, and rewrites
# .pins only after a rebuild, so objects rebuild exactly when a pin changes.
WASM_DEPS_SH := scripts/wasm-deps.sh
WASM_NO_DEPS := $(WASM_DEPS_SH) is not in the release tarball; build wasm from the git tree

wasm-deps:
	@test -f $(WASM_DEPS_SH) || { echo "make wasm: $(WASM_NO_DEPS)" >&2; exit 1; }
	@sh $(WASM_DEPS_SH) $(WASM_DEPS)

$(WASM_PINS):
	@test -f $(WASM_DEPS_SH) || { echo "make wasm: $(WASM_NO_DEPS)" >&2; exit 1; }
	sh $(WASM_DEPS_SH) $(WASM_DEPS)

$(WASM_DIR)/obj/%.o: $(SRCDIR)/%.c $(WASM_PINS)
	@mkdir -p $(WASM_DIR)/obj
	$(WASM_CC) $(WASM_CFLAGS) -MMD -MP -c -o $@ $<

-include $(WASM_OBJS:.o=.d)

$(WASM_DIR)/libsigma.a: $(WASM_OBJS)
	$(WASM_AR) rcs $@ $(WASM_OBJS)

$(WASM_DIR)/sigma_cli.wasm: $(SRCDIR)/sigma_cli.c $(WASM_DIR)/libsigma.a $(wildcard $(SRCDIR)/*.h)
	$(WASM_CC) $(WASM_CFLAGS) $(WASM_LDFLAGS) -o $@ $(SRCDIR)/sigma_cli.c \
		$(WASM_DIR)/libsigma.a $(WASM_LIBS)

# test_sigma_match times its |re match-limit case with clock(), which WASI
# only provides through the process-clock emulation library.
$(WASM_DIR)/test_sigma_match.wasm: $(SRCDIR)/test_sigma_match.c $(WASM_DIR)/libsigma.a $(wildcard $(SRCDIR)/*.h)
	$(WASM_CC) $(WASM_CFLAGS) -D_WASI_EMULATED_PROCESS_CLOCKS $(WASM_LDFLAGS) -o $@ $< \
		$(WASM_DIR)/libsigma.a $(WASM_LIBS) -lwasi-emulated-process-clocks

$(WASM_DIR)/test_%.wasm: $(SRCDIR)/test_%.c $(WASM_DIR)/libsigma.a $(wildcard $(SRCDIR)/*.h)
	$(WASM_CC) $(WASM_CFLAGS) $(WASM_LDFLAGS) -o $@ $< $(WASM_DIR)/libsigma.a $(WASM_LIBS)

# The module a WebAssembly host loads: a WASI reactor (no main) exporting
# the sigma_wasm_* entry points of sigma_wasm.c over sigma_events.c.
# --strip-all drops the function-name section (about 40% of the bytes);
# exports keep their names.
WASM_MODULE      := $(WASM_DIR)/libsigma.wasm
WASM_MODULE_OBJS := $(WASM_DIR)/obj/sigma_wasm.o $(WASM_DIR)/obj/sigma_events.o

-include $(WASM_MODULE_OBJS:.o=.d)

$(WASM_MODULE): $(WASM_MODULE_OBJS) $(WASM_DIR)/libsigma.a
	$(WASM_CC) $(WASM_CFLAGS) -mexec-model=reactor $(WASM_LDFLAGS) -Wl,--strip-all -o $@ \
		$(WASM_MODULE_OBJS) $(WASM_DIR)/libsigma.a $(WASM_LIBS)

$(WASM_DIR)/test_events.wasm: $(SRCDIR)/test_events.c $(WASM_DIR)/obj/sigma_events.o $(WASM_DIR)/libsigma.a $(wildcard $(SRCDIR)/*.h)
	$(WASM_CC) $(WASM_CFLAGS) $(WASM_LDFLAGS) -o $@ $< $(WASM_DIR)/obj/sigma_events.o \
		$(WASM_DIR)/libsigma.a $(WASM_LIBS)

wasm:
	@$(MAKE) --no-print-directory wasm-deps
	@$(MAKE) --no-print-directory $(WASM_DIR)/libsigma.a $(WASM_DIR)/sigma_cli.wasm $(WASM_MODULE)

# fuzz_simd is native only: wasm32 has no vector path to compare with scalar.
# test_corr_concurrency is native only: wasm32-wasip1 has no threads.
wasm-test: wasm
	@$(MAKE) --no-print-directory $(patsubst %,$(WASM_DIR)/%.wasm,$(WASM_TESTS) test_events)
	@test -x $(WASMTIME) || { echo "wasm-test: no wasmtime at $(WASMTIME); pass WASMTIME="; exit 1; }
	@for t in $(WASM_TESTS); do \
		echo "--- $$t.wasm"; \
		$(WASM_RUN) $(WASM_DIR)/$$t.wasm || exit 1; \
	done
	@SIGMAC_SRC=$(SIGMAC_SRC) $(SIGMAC_PY) $(SRCDIR)/conformance_emit.py $(WASM_DIR)/conf.sigmac
	@echo "--- test_events.wasm"
	$(WASM_RUN) $(WASM_DIR)/test_events.wasm $(WASM_DIR)/conf.sigmac \
		$(ARCH_FIX)/arch.sigmac $(ARCH_FIX)/arch.corr.json
	@echo "--- conformance (sigma_cli.wasm)"
	@printf '$(CONF_EVENTS)' > $(WASM_DIR)/conf_ev.tsv
	@out=$$($(WASM_RUN) $(WASM_DIR)/sigma_cli.wasm $(WASM_DIR)/conf.sigmac < $(WASM_DIR)/conf_ev.tsv); echo "$$out"; \
	 for r in $(CONF_RULES); do echo "$$out" | grep -q "rule=$$r" || { echo "WASM CONFORMANCE FAIL: rule $$r did not fire"; exit 1; }; done; \
	 echo "WASM CONFORMANCE OK: 6/6 rules"
	@echo "--- arch fixture (sigma_cli.wasm vs NEON golden)"
	$(WASM_RUN) $(WASM_DIR)/sigma_cli.wasm $(ARCH_FIX)/arch.sigmac $(ARCH_FIX)/arch.corr.json \
		< $(ARCH_FIX)/arch.tsv > $(WASM_DIR)/arch-wasm.txt
	diff -u $(ARCH_FIX)/arch.dump $(WASM_DIR)/arch-wasm.txt
	@echo "wasm-test: wasm32 == NEON golden (matcher + corr), all engine tests passed"

install: all
	install -d $(DESTDIR)$(PREFIX)/lib
	install -d $(DESTDIR)$(PREFIX)/include/sigma
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PCDIR)
	install -m 0755 $(BUILDDIR)/$(SHLIB) $(DESTDIR)$(PREFIX)/lib/
	ln -sf $(SHLIB) $(DESTDIR)$(PREFIX)/lib/$(SHLIB_SONAME)
	ln -sf $(SHLIB) $(DESTDIR)$(PREFIX)/lib/$(SHLIB_LINK)
	install -m 0644 $(BUILDDIR)/libsigma.a $(DESTDIR)$(PREFIX)/lib/
	install -m 0644 $(HEADERS) $(DESTDIR)$(PREFIX)/include/sigma/
	install -m 0755 $(BUILDDIR)/sigma_cli $(DESTDIR)$(PREFIX)/bin/sigma_cli
	install -m 0644 sigma.pc $(DESTDIR)$(PCDIR)/

clean:
	rm -rf $(BUILDDIR) crash-* leak-* timeout-* sigma.pc \
	    $(SRCDIR)/fuzz_corpus/load/seed.sigmac
