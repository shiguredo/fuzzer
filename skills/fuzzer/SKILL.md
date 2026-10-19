---
name: fuzzer
description: Erlang の関数を libFuzzer で fuzzing するための時雨堂 fuzzer ライブラリと rebar3_fuzzer プラグインのリファレンス。fuzz target の実装、feature bitmap の設計、fuzzer:run/1 と rebar3_fuzzer の実行、コーパスと artifact、クラッシュレポート、Erlang カバレッジ、制約と落とし穴に関する実装・レビュー・質問時に使用する。
---

# fuzzer

Erlang で実装した関数を libFuzzer から実行するためのライブラリ。
libFuzzer は NIF に直接リンクし、入力の生成、コーパスの更新、クラッシュ入力の保存を担当する。
Erlang は libFuzzer が生成したバイナリーを受け取り、fuzz target の `evaluate/1` を実行する。

## 最初に読むもの

- 使い方、ビルド、fuzz target の実装、実行 API、rebar3_fuzzer、コーパス、クラッシュレポート、カバレッジ、制約は `doc/USAGE.md` に集約している。
- `rebar3_fuzzer` の詳細は `rebar3_fuzzer/README.md` を参照する。
- 公開 API の最新状態は `src/fuzzer.erl`、NIF の挙動は `c_src/fuzzer_nif.c` を正とする。ドキュメントと食い違ったらソースを優先する。
- リポジトリ内で開発するときは `CODEBASE.md` の指示に従う。
- Erlang コードを書く・変更するときは `shiguredo-erlang` スキルも参照する。

## これを外すと壊れる契約

- fuzz target は `fuzzer_target` behaviour の `evaluate/1` を実装し、`{ok, Features}` か `crash` を返す。
- `Features` は `0` 以上 `16#FFFFFFFFFFFFFFFF` 以下の整数である。
- パーサーが返す通常の入力エラーは `crash` ではなく feature に割り当てる。`crash` にすると libFuzzer がその入力を直ちにクラッシュとして保存する。
- 例外を自分で catch して `crash` を返さない。例外は fuzzer に伝播させ、クラッシュレポートに理由とスタックトレースを残す。
- ワーカーは fuzzing の間ずっと 1 個のプロセスを使い回す。状態を持つ fuzz target は `reset/0` で入力ごとに初期化する。
- `fuzzer:run/1` と `fuzzer:run/5` は fuzzing 専用の BEAM で呼ぶ。クラッシュ時は BEAM 全体が abort し、Erlang 側の後始末は行われない。
- 同じ BEAM で同時に実行できる `fuzzer:run/1` は 1 件だけである。`jobs` / `workers` は `fuzzer:run/1` では未対応であり、並列実行には `rebar3_fuzzer --jobs` か別々の BEAM を使う。
- `feedback` に指定したモジュールは、fuzzing 中に計測用コードへ置き換えられる。fuzzing 中にリロードしてはならない。`feedback` と `cover` は同時に指定できない。
- `feedback` の対象モジュールは `+debug_info` 付きでコンパイルされている必要がある。`line` は native coverage が必要で、`clause` は parse transform を使う。
- `on_crash` の既定値は `abort` である。`continue` では同じ BEAM で fuzzing を続け、`crash_id` で重複を除いたクラッシュを `crashes` に返す。タイムアウト時はワーカーを作り直す。タイムアウト以外でワーカーが落ちた場合は `continue` でも abort する。クラッシュを検出した場合、`rebar3_fuzzer` の終了コードは 0 にならない。
- `auto_dict` の既定値は `true` である。target と feedback のモジュールのリテラルから辞書を自動生成し、`dict` の利用者辞書と 1 ファイルにまとめる。`dict_modules` で target 以外の生成元を追加できる。binary 内の型指定のない文字列は latin1 として扱う。
- `init/0` は最初の入力の直前に呼ばれ、タイムアウトでワーカーを作り直すと新しいワーカーでも呼ばれる。名前付き ETS などを使う場合は冪等にする。タイムアウトで kill されたワーカーの `terminate/0` は呼ばれない。

## バージョンの確認

NIF に静的リンクした libFuzzer のバージョンは `fuzzer:libfuzzer_version/0` で確認できる。
値は NIF をビルドした Clang のバージョンであり、compiler-rt に含まれる libFuzzer のバージョンに対応する。
`make toolchain-info` でも同じバージョンを確認できる。

## 探索が進まないときの確認

- 到達してほしい分岐や状態を feature bitmap に割り当てているか。
- 通常の入力エラーを `crash` にして、探索を早期に打ち切っていないか。
- 例外を自分で catch して `crash` を返し、理由とスタックトレースを捨てていないか。
- 入力サイズなどの動的な値を bit に割り当てて、feature が爆発していないか。
- 外部 I/O、乱数、時刻に依存して、同じ入力で同じ結果を返さなくなっていないか。
- Erlang コードのカバレッジを探索に使いたい場合、`feedback` に対象モジュールを指定しているか。
- `feedback` のモード (`line` / `clause`) と 1 入力あたりのコストを理解しているか。`cover` は実行後の集計専用であり、`feedback` とは併用できない。
- `feedback` の対象モジュールが `+debug_info` 付きで、fuzzing 中にリロードされないか。

## 変更時の確認

ビルド、テスト、lint の手順は `doc/DEVELOPMENT.md` を参照する。
`fuzzer` は OTP 29.1 以上と、Clang と同じバージョンの compiler-rt を要求する。
