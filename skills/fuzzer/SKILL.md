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
- ワーカーは fuzzing の間ずっと 1 個のプロセスを使い回す。状態を持つ fuzz target は `reset/0` で入力ごとに初期化する。
- `fuzzer:run/1` と `fuzzer:run/5` は fuzzing 専用の BEAM で呼ぶ。クラッシュ時は BEAM 全体が abort し、Erlang 側の後始末は行われない。
- 同じ BEAM で同時に実行できる `fuzzer:run/1` は 1 件だけである。`jobs` / `workers` は `fuzzer:run/1` では未対応であり、並列実行には `rebar3_fuzzer --jobs` か別々の BEAM を使う。

## 探索が進まないときの確認

- 到達してほしい分岐や状態を feature bitmap に割り当てているか。
- 通常の入力エラーを `crash` にして、探索を早期に打ち切っていないか。
- 入力サイズなどの動的な値を bit に割り当てて、feature が爆発していないか。
- 外部 I/O、乱数、時刻に依存して、同じ入力で同じ結果を返さなくなっていないか。
- Erlang bytecode の分岐 coverage は libFuzzer の探索に使われないことを理解しているか。`cover` は実行後の集計専用である。

## 変更時の確認

ビルド、テスト、lint の手順は `doc/DEVELOPMENT.md` を参照する。
`fuzzer` は OTP 29.1 以上と、Clang と同じバージョンの compiler-rt を要求する。
