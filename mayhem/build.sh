#!/usr/bin/env bash
#
# mayhem/build.sh — builds, inside the commit image as `mayhem` in /mayhem:
#   1. rspamd's server library with $SANITIZER_FLAGS + libFuzzer coverage + DWARF 3  (mayhem/build-fuzz)
#   2. each harness in mayhem/ twice: /mayhem/<name> (libFuzzer) and /mayhem/<name>-standalone
#   3. rspamd's own unit tests and rspamadm with the project's normal flags (mayhem/build-test)
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
FUZZ_BUILD="$SRC/mayhem/build-fuzz"
TEST_BUILD="$SRC/mayhem/build-test"

# The project's clang flag set appends -gdwarf-4 and ThinLTO to Debug/RelWithDebInfo/Release builds, so the
# fuzz tree uses a custom build type (no per-config flags) and passes every flag itself.
# UBSan checks relaxed (everything else, and all of ASan, stays halting):
#  function          rspamd and GLib call destructors/callbacks through `void (*)(void *)` pointers to functions
#                    with typed parameters; reported on every message teardown.
#  enum              the HTML parser stores hashes of unknown tag names in a `tag_id_t` (a plain C enum) via int
#                    casts, so every unknown tag loads an out-of-range enum value (html.cxx, html_tag_defs.hxx).
#  nonnull-attribute rspamd_url_parse() memcmp()s against the NULL name of its PROTOCOL_UNKNOWN table entry with
#                    length 0 (url.c); harmless, but hit by the first scheme-less input.
RELAX="-fno-sanitize=function,enum,nonnull-attribute"
FUZZ_FLAGS="$SANITIZER_FLAGS $RELAX -O1 $DEBUG_FLAGS -fsanitize=fuzzer-no-link"

# 1) sanitized project, instrumented for coverage
cmake -S . -B "$FUZZ_BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Fuzz -DENABLE_LTO=OFF \
	-DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
	-DCMAKE_C_FLAGS="$FUZZ_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS" \
	-DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DENABLE_BACKWARD=OFF -DINSTALL_WEBUI=OFF -DENABLE_LUAJIT=ON
cmake --build "$FUZZ_BUILD" -j"$MAYHEM_JOBS" --target rspamd-server

# 2) harnesses. Compile flags (defines + include dirs) come from how the project compiles its own sources;
#    the link line comes from how it links its unit-test binary, minus that binary's objects.
cd "$FUZZ_BUILD"
python3 - "$FUZZ_BUILD" <<'PY'
import json, shlex, sys
bd = sys.argv[1]
want = {"c": "src/libmime/message.c", "cxx": "src/libserver/html/html.cxx"}
out = {}
for e in json.load(open(bd + "/compile_commands.json")):
    for k, suffix in want.items():
        if e["file"].endswith(suffix):
            toks, keep, i = shlex.split(e["command"]), [], 0
            while i < len(toks):
                t = toks[i]
                if t.startswith(("-D", "-I")):
                    keep.append(t)
                elif t == "-isystem":
                    keep += [t, toks[i + 1]]
                    i += 1
                elif t.startswith("-std="):
                    keep.append(t)
                i += 1
            out[k] = keep
for k in want:
    open(bd + "/harness_%s.flags" % k, "w").write(" ".join(shlex.quote(t) for t in out[k]) + "\n")
PY
HFLAGS_CXX="$(cat harness_cxx.flags) -fPIC"

link_args="$(ninja -t commands test/rspamd-test-cxx | tail -1 | python3 -c '
import shlex, sys
toks = shlex.split(sys.stdin.read())
i = toks.index("-o") + 2
toks = toks[i:]
toks = [t for t in toks if t not in ("&&", ":")]
print(" ".join(shlex.quote(t) for t in toks))
')"

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o standalone_main.o

for h in fuzz_mime fuzz_url fuzz_html fuzz_ucl fuzz_archive; do
	$CXX $SANITIZER_FLAGS $RELAX -O1 $DEBUG_FLAGS $LIB_FUZZING_ENGINE $HFLAGS_CXX -I"$SRC/mayhem" -DMAYHEM_SRCDIR="\"$SRC\"" \
		-c "$SRC/mayhem/$h.cc" -o "$h.o"
	eval "$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -fuse-ld=lld $h.o lsan_off.o $link_args -o $SRC/$h"

	$CXX $SANITIZER_FLAGS $RELAX -O1 $DEBUG_FLAGS $HFLAGS_CXX -I"$SRC/mayhem" -DMAYHEM_SRCDIR="\"$SRC\"" \
		-c "$SRC/mayhem/$h.cc" -o "$h-sa.o"
	eval "$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -fuse-ld=lld $h-sa.o standalone_main.o lsan_off.o $link_args -o $SRC/$h-standalone"
done

# 3) the project's own tests with normal flags (an independent build, no sanitizers)
cd "$SRC"
cmake -S . -B "$TEST_BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=OFF \
	-DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
	-DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
	-DENABLE_BACKWARD=OFF -DINSTALL_WEBUI=OFF -DENABLE_LUAJIT=ON
cmake --build "$TEST_BUILD" -j"$MAYHEM_JOBS" --target rspamd-test-cxx rspamadm
