APP := fuzzer
ERL ?= erl
REBAR3 ?= rebar3

UNAME_S := $(shell uname -s)

ifeq ($(origin CC),default)
ifeq ($(UNAME_S),Darwin)
ifneq ($(wildcard /opt/homebrew/opt/llvm/bin/clang),)
CC := /opt/homebrew/opt/llvm/bin/clang
else
CC := clang
endif
else
CC := clang
endif
endif

EBIN_DIR := $(abspath _build/default/lib/$(APP)/ebin)
FUZZ_BUILD_DIR := _build/fuzz
RTP_CORPUS := $(FUZZ_BUILD_DIR)/rtp/corpus
RTP_ARTIFACTS := $(FUZZ_BUILD_DIR)/rtp/artifacts
SDP_CORPUS := $(FUZZ_BUILD_DIR)/sdp/corpus
SDP_ARTIFACTS := $(FUZZ_BUILD_DIR)/sdp/artifacts
ERTS_INCLUDE_DIR := $(shell $(ERL) -noshell -eval 'io:format("~ts", [filename:join([code:root_dir(), "erts-" ++ erlang:system_info(version), "include"])]), halt().')
NIF := priv/fuzzer_nif.so
CLANG_RUNTIME_DIR := $(shell $(CC) --print-runtime-dir)
# clang --print-runtime-dir はターゲットトリプル付きのディレクトリーを返すことがある。
# その場合は親の lib ディレクトリー配下に libFuzzer のランタイムが置かれる。
CLANG_LIB_DIR := $(abspath $(CLANG_RUNTIME_DIR)/..)
LINUX_ARCH := $(shell uname -m)
# libFuzzer は compiler-rt の一部であり、Clang と同じバージョンで配布される。
# ビルドに使う Clang のバージョンを NIF へ埋め込み、Erlang から確認できるようにする。
LIBFUZZER_VERSION := $(shell $(CC) -dumpversion)

CFLAGS := -std=c11 -Wall -Wextra -Werror

ifeq ($(UNAME_S),Darwin)
NIF_LDFLAGS := -dynamiclib -undefined dynamic_lookup
# Homebrew の LLVM はランタイムを darwin ディレクトリーへ置く
FUZZER_NO_MAIN := $(firstword $(wildcard \
    $(CLANG_RUNTIME_DIR)/libclang_rt.fuzzer_no_main_osx.a \
    $(CLANG_LIB_DIR)/darwin/libclang_rt.fuzzer_no_main_osx.a))
# macOS の Clang は libc++ を標準ライブラリとして使う
NIF_CXX_RUNTIME := -lc++
else
NIF_LDFLAGS := -shared
# Ubuntu の libclang-rt は linux ディレクトリーへランタイムを置く
FUZZER_NO_MAIN := $(firstword $(wildcard \
    $(CLANG_RUNTIME_DIR)/libclang_rt.fuzzer_no_main-$(LINUX_ARCH).a \
    $(CLANG_LIB_DIR)/linux/libclang_rt.fuzzer_no_main-$(LINUX_ARCH).a \
    $(CLANG_LIB_DIR)/libclang_rt.fuzzer_no_main-$(LINUX_ARCH).a))
# Linux の compiler-rt は libstdc++ でビルドされている
NIF_CXX_RUNTIME := -lstdc++
endif

NIF_CFLAGS := $(CFLAGS) -g -O1 -fPIC -fno-omit-frame-pointer -fsanitize=fuzzer-no-link -I$(ERTS_INCLUDE_DIR) \
              -DFUZZER_LIBFUZZER_VERSION='"$(LIBFUZZER_VERSION)"'

.PHONY: all compile erlang nif test plugin-test lint fuzz-smoke fuzz-rtp fuzz-rtp-smoke fuzz-sdp fuzz-sdp-smoke clean prepare-rtp prepare-sdp toolchain-info publish

all: compile

compile: erlang nif

erlang:
	$(REBAR3) compile

nif: $(NIF)

$(NIF): c_src/fuzzer_nif.c
	@if [ -z "$(FUZZER_NO_MAIN)" ]; then \
		echo "libclang_rt.fuzzer_no_main が見つかりません。" >&2; \
		echo "Clang と同じバージョンの compiler-rt をインストールしてください。" >&2; \
		echo "clang --print-runtime-dir: $(CLANG_RUNTIME_DIR)" >&2; \
		exit 1; \
	fi
	mkdir -p priv
	$(CC) $(NIF_CFLAGS) $(NIF_LDFLAGS) $< $(FUZZER_NO_MAIN) $(NIF_CXX_RUNTIME) -o $@

test: compile
	$(REBAR3) xref
	$(REBAR3) eunit
	$(MAKE) plugin-test

plugin-test:
	cd rebar3_fuzzer && $(REBAR3) eunit
	cd rebar3_fuzzer && $(REBAR3) xref

# efmt / elint / clang-format は prek.toml のフックで実行する
lint:
	prek run efmt efmt-check elint clang-format --all-files

prepare-rtp: compile
	mkdir -p $(RTP_CORPUS) $(RTP_ARTIFACTS)
	xxd -r -p examples/rtp/corpus/minimal.hex $(RTP_CORPUS)/minimal
	xxd -r -p examples/rtp/corpus/extension.hex $(RTP_CORPUS)/extension
	xxd -r -p examples/rtp/corpus/padding.hex $(RTP_CORPUS)/padding

prepare-sdp: compile
	mkdir -p $(SDP_CORPUS) $(SDP_ARTIFACTS)
	xxd -r -p examples/sdp/corpus/minimal.hex $(SDP_CORPUS)/minimal
	xxd -r -p examples/sdp/corpus/media.hex $(SDP_CORPUS)/media

fuzz-smoke: fuzz-rtp-smoke fuzz-sdp-smoke

fuzz-rtp: prepare-rtp
	$(ERL) -noshell -pa $(EBIN_DIR) -eval 'case fuzzer:run(fuzzer_example_rtp_fuzz_target, 0, 2048, "$(abspath $(RTP_CORPUS))", "$(abspath $(RTP_ARTIFACTS))/") of 0 -> halt(0); Code -> halt(Code) end.'

fuzz-rtp-smoke: prepare-rtp
	$(ERL) -noshell -pa $(EBIN_DIR) -eval 'case fuzzer:run(fuzzer_example_rtp_fuzz_target, 10000, 2048, "$(abspath $(RTP_CORPUS))", "$(abspath $(RTP_ARTIFACTS))/") of 0 -> halt(0); Code -> halt(Code) end.'

fuzz-sdp: prepare-sdp
	$(ERL) -noshell -pa $(EBIN_DIR) -eval 'case fuzzer:run(fuzzer_example_sdp_fuzz_target, 0, 16384, "$(abspath $(SDP_CORPUS))", "$(abspath $(SDP_ARTIFACTS))/") of 0 -> halt(0); Code -> halt(Code) end.'

fuzz-sdp-smoke: prepare-sdp
	$(ERL) -noshell -pa $(EBIN_DIR) -eval 'case fuzzer:run(fuzzer_example_sdp_fuzz_target, 10000, 16384, "$(abspath $(SDP_CORPUS))", "$(abspath $(SDP_ARTIFACTS))/") of 0 -> halt(0); Code -> halt(Code) end.'

toolchain-info:
	$(CC) --version
	$(CC) --print-runtime-dir
	@if [ -n "$(FUZZER_NO_MAIN)" ]; then \
		echo "libFuzzer runtime: $(FUZZER_NO_MAIN)"; \
		echo "libFuzzer version: $(LIBFUZZER_VERSION)"; \
	else \
		echo "libclang_rt.fuzzer_no_main が見つかりません。" >&2; \
		exit 1; \
	fi

clean:
	$(REBAR3) clean
	cd rebar3_fuzzer && $(REBAR3) clean
	rm -f $(NIF)
	rm -rf $(NIF).dSYM
	rm -rf $(FUZZ_BUILD_DIR)

# kvconf と同じく rebar3_hex で Hex へ公開する
publish:
	$(REBAR3) hex publish package
