# fuzzer

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?logo=discord&logoColor=white)](https://discord.gg/shiguredo)

## About Shiguredo's open source software

We will not respond to PRs or issues that have not been discussed on Discord. Also, Discord is only available in Japanese.

Please read <https://github.com/shiguredo/oss> before use.

## 時雨堂のオープンソースソフトウェアについて

利用前に <https://github.com/shiguredo/oss> をお読みください。

## 概要

`fuzzer` は、Erlang で実装した関数を libFuzzer から実行するためのライブラリです。

## 使い方

fuzz target を実装します。`evaluate/1` が入力を処理し、到達した状態を feature bitmap として返します。

```erlang
-module(example_fuzz_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).

-spec evaluate(binary()) -> {ok, non_neg_integer()} | crash.
evaluate(Data) ->
    % example_parser は利用者が用意する対象の関数
    % 到達した状態を feature bitmap として返す
    try example_parser:decode(Data) of
        {ok, _Value} -> {ok, 1};
        {error, _Reason} -> {ok, 1 bsl 1}
    catch
        _:_ -> crash
    end.
```

`fuzzer:run/1` で実行します。

```erlang
fuzzer:run(#{target => example_fuzz_target, runs => 10000}).
```

rebar3 から実行する場合は `rebar3_fuzzer` を使います。

```console
$ rebar3 fuzzer --target example_fuzz_target --runs 10000
```

Hex パッケージは未公開のため、現状はこのリポジトリをチェックアウトして利用します。
導入方法、オプション、コーパス、クラッシュレポートは [doc/USAGE.md](doc/USAGE.md) を参照してください。

## 動作環境

ビルドには Erlang/OTP 29.1 以上、rebar3、Clang と compiler-rt、`xxd` が必要です。

## ドキュメント

| ドキュメント | 内容 |
| --- | --- |
| [doc/USAGE.md](doc/USAGE.md) | ライブラリの使い方 |
| [doc/DEVELOPMENT.md](doc/DEVELOPMENT.md) | ビルド、テスト、サンプル、Hex パッケージ |
| [skills/fuzzer/SKILL.md](skills/fuzzer/SKILL.md) | LLM 向けのリファレンスと守るべき契約 |
| [rebar3_fuzzer/README.md](rebar3_fuzzer/README.md) | rebar3 プラグインの詳細 |

## libFuzzer ライセンス

本ソフトウェアは libFuzzer のランタイム (`libclang_rt.fuzzer_no_main`) を NIF に静的リンクしています。
そのため、ビルドした `priv/fuzzer_nif.so` には libFuzzer のコードが含まれます。
libFuzzer は LLVM プロジェクトの一部で、Apache License 2.0 with LLVM Exceptions で配布されています。
ライセンス本文は `THIRD_PARTY_LICENSES.md` に同梱しています。

- <https://llvm.org/LICENSE.txt>

## ライセンス

Apache License 2.0

```text
Copyright 2026, Shiguredo Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
