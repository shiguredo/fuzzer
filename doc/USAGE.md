# fuzzer の使い方

`fuzzer` は、Erlang で実装した関数を libFuzzer から実行するためのライブラリである。
libFuzzer は NIF に直接リンクし、入力の生成、コーパスの更新、クラッシュ入力の保存を担当する。
Erlang は libFuzzer が生成したバイナリーを受け取り、対象の関数を実行する。

このリポジトリには、RTP パーサーと SDP パーサーを fuzzing するサンプルが含まれる。
rebar3 から fuzzing を実行する `rebar3_fuzzer` も含まれる。
現在は Hex パッケージを公開していないため、現状はリポジトリをチェックアウトして利用する。
リポジトリ自体のビルドとテストは `doc/DEVELOPMENT.md` を参照する。

## 動作環境

ビルドには次のツールが必要になる。

- Erlang/OTP 29.1 以上
- rebar3
- Clang
- Clang と同じバージョンの compiler-rt (`libclang_rt.fuzzer_no_main`)
- `xxd` (サンプルの初期コーパス変換に使用)

macOS の Xcode に付属する Apple Clang は、libFuzzer のランタイムを含まない場合がある。
Makefile は `/opt/homebrew/opt/llvm/bin/clang` が存在する場合、この Clang を優先する。

現在は次の環境で動作を確認している。

- Erlang/OTP 29.1.2
- rebar3 3.27.3
- Ubuntu 26.04 (x86_64 / aarch64) + 最新の Clang
- macOS 26 (Apple Silicon) + Homebrew LLVM

`fuzzer` は OTP 29.1 以上を要求する。
ライブラリ本体が OTP 27.2 を要求するプロジェクト (例: sora-stun) でも、fuzzing 専用の CI ジョブだけ OTP 29.1 を使えば導入できる。

使用する Clang とランタイムの場所は、次のコマンドで確認できる。

```console
$ make toolchain-info
```

`libclang_rt.fuzzer_no_main` が見つからない場合は、Clang と同じバージョンの compiler-rt をインストールする。

## 利用プロジェクトへの導入

`fuzzer` と `rebar3_fuzzer` を Hex パッケージとして公開した後は、利用するプロジェクトの `rebar.config` に次の設定を追加する。

```erlang
{deps, [fuzzer]}.
{project_plugins, [rebar3_fuzzer]}.
```

`rebar3_fuzzer` は、fuzzer アプリケーションの `Makefile` を使って NIF をビルドする。
そのため、`fuzzer` が依存関係またはプロジェクトアプリとして存在している必要がある。

## fuzz target の実装

**fuzz target** は、libFuzzer の入力を Erlang の対象関数へ渡し、実行結果を **feature bitmap** に変換するモジュールである。
fuzz target は `fuzzer_target` behaviour を実装する。

```erlang
-module(example_fuzz_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).

-spec evaluate(binary()) -> {ok, non_neg_integer()} | crash.
evaluate(Data) ->
    try example_parser:decode(Data) of
        {ok, Value} ->
            {ok, success_features(Value)};
        {error, too_short} ->
            {ok, 1 bsl 0};
        {error, invalid_header} ->
            {ok, 1 bsl 1}
    catch
        _Class:_Reason:_Stacktrace ->
            crash
    end.

-spec success_features(term()) -> non_neg_integer().
success_features(Value) ->
    Base = 1 bsl 2,
    case Value of
        #{extension := true} -> Base bor (1 bsl 3);
        _ -> Base
    end.
```

`evaluate/1` は、次のいずれかを返す。

- `{ok, Features}`: 入力を処理できた場合。`Features` は `0` 以上 `16#FFFFFFFFFFFFFFFF` 以下の整数
- `crash`: クラッシュ入力として扱う場合

パーサーが不正な入力を通常のエラーとして返した場合、その結果を feature に割り当てる。
通常の入力エラーを `crash` にすると、libFuzzer はその入力を直ちにクラッシュとして保存する。

### コールバック

fuzz target は次のコールバックを実装できる。

| コールバック | 呼び出しタイミング |
| --- | --- |
| `init/0` | ワーカーの起動時に 1 回 |
| `reset/0` | 各入力の `evaluate/1` の直前 |
| `terminate/0` | ワーカーの停止時 |

ワーカーは fuzzing の間ずっと 1 個のプロセスを使い回す。
プロセス辞書や ETS などに状態を持つ fuzz target は、`reset/0` で状態を初期化する。

### feature bitmap の設計

`Features` の各 bit には、fuzz target が到達した意味的な状態を割り当てる。
同じ入力で複数の状態へ到達した場合は、対応する bit を `bor` で結合する。

- 例外、`{ok, Features}` 以外の戻り値、64 bit の範囲外の feature はクラッシュ扱いになる。
- NIF は feature bitmap の各 bit と bitmap 全体のハッシュを libFuzzer のカウンターへ登録する。
- ハッシュ用のカウンターは 65,536 個しかないため、bit の組み合わせが衝突する可能性がある。
- 動的な値 (入力サイズそのものなど) を bit にすると feature が爆発する。意味のある状態だけを bit にする。

### 設計指針

- 同じ入力に対して同じ結果を返すこと。乱数、時刻、外部 I/O に依存しない。
- ファイル、ネットワーク、ポートなどの外部資源を `evaluate/1` から触らない。
- `evaluate/1` は libFuzzer から大量に呼ばれる。重い初期化は `init/0` に置く。
- 状態を持つ fuzz target は `reset/0` を実装し、入力間で状態を持ち越さない。
- 入力の検証で見つけた異常を、できるだけクラッシュではなく意味のある feature にする。
- 到達してほしい分岐や状態を feature として明示する。これを設計しないと探索が進まない。

### 実装例

RTP と SDP の実装例は、次のファイルにある。

- `examples/rtp/src/fuzzer_example_rtp_fuzz_target.erl`
- `examples/sdp/src/fuzzer_example_sdp_fuzz_target.erl`

## fuzzer の実行 API

`fuzzer:run/1` にオプションマップを渡して fuzzing を開始する。

```erlang
fuzzer:run(#{target => example_fuzz_target,
             runs => 10000,
             max_length => 4096,
             corpus => "_build/fuzz/example/corpus",
             artifacts => "_build/fuzz/example/artifacts"}).
```

戻り値は次のマップになる。

```erlang
#{exit_code => 0,
  coverage => undefined | #{module() => #{covered => ..., ...}}}
```

`coverage` は `cover` オプションを指定した場合だけマップになる。

### オプション

| オプション | 型 | 既定値 | 説明 |
| --- | --- | --- | --- |
| `target` | `module()` | 必須 | `fuzzer_target` behaviour を実装したモジュール |
| `runs` | `non_neg_integer()` | `0` | 実行回数。`0` はクラッシュ検出か中断まで継続 |
| `max_length` | `pos_integer()` | `4096` | 入力の最大バイト数 |
| `corpus` | `file:filename_all()` | `_build/fuzz/<target>/corpus` | コーパスディレクトリー |
| `artifacts` | `file:filename_all()` | `_build/fuzz/<target>/artifacts` | クラッシュ入力の保存先 |
| `dict` | `file:filename_all()` | なし | libFuzzer の辞書ファイル |
| `timeout` | `pos_integer()` | なし | 1 入力あたりのタイムアウト秒。Erlang の watchdog が監視する |
| `max_total_time` | `non_neg_integer()` | なし | fuzzing 全体の制限時間秒。`0` は無制限 |
| `seed` | `non_neg_integer()` | なし | 乱数シード。上限は `16#FFFFFFFFFFFFFFFF` |
| `rss_limit_mb` | `pos_integer()` | libFuzzer の既定値 | RSS の上限 (MB) |
| `cover` | `[module()]` | `[]` | Erlang カバレッジを計測するモジュール |
| `extra_args` | `[string() \| binary()]` | `[]` | libFuzzer へそのまま渡す追加引数 |

パスには文字列とバイナリーのどちらも指定できる。
文字列は UTF-8 として扱うため、日本語を含むパスも利用できる。
`corpus` と `artifacts` のディレクトリーが存在しない場合は作成する。
`artifacts` の末尾に `/` がない場合は自動で付与する。

`dict` は存在する通常ファイルでなければならない。
`target` はコードパス上に存在するモジュールでなければならない。
未知のキーを渡すと `error({invalid_option, {unknown, Keys}})` になる。

`extra_args` には libFuzzer の追加フラグを渡せる。
ただし `-jobs` と `-workers` は埋め込みドライバーでは動かないため拒否される。
`-timeout` を `extra_args` で指定すると Erlang の watchdog と競合する。入力タイムアウトには `timeout` オプションを使う。

### 並列実行に関する注意

`fuzzer:run/1` の `jobs` と `workers` は未対応である。
NIF に埋め込んだドライバーでは子プロセスを起動できないため、指定すると `error({invalid_option, ...})` になる。

同じ BEAM では同時に 1 件の `fuzzer:run/1` だけを実行できる。
同時に呼ぶと NIF が `busy` 例外を送出する。
並列実行したい場合は `rebar3_fuzzer --jobs N` を使うか、別々の BEAM で `fuzzer:run/1` を実行する。

### 従来の位置引数 API

`fuzzer:run/5` は互換性のために残している。
戻り値は `exit_code` だけであり、新規のコードでは `run/1` を使う。

```erlang
fuzzer:run(Target, Runs, MaxLength, CorpusDir, ArtifactDir).
```

### 1 入力の再実行

`fuzzer:run_one/2` で 1 つの入力を再実行できる。
`fuzzer:reproduce/2` は artifact ファイルを読み込んで再実行する。

```erlang
{ok, Features} = fuzzer:run_one(example_fuzz_target, <<"input">>),
{crash, Report} = fuzzer:reproduce(example_fuzz_target, "crash-<SHA-1>").
```

`run_one/2` は fuzzing のワーカーと同じ順序で `init/0`、`reset/0`、`evaluate/1`、`terminate/0` を呼ぶ。
クラッシュしても BEAM を終了せず、`{crash, Report}` として返す。
60 秒を超えると `{error, timeout}` を返す。

`reproduce/2` はファイルを読めない場合に `{error, {file, Path, Reason}}` を返す。

### BEAM のライフサイクル

`fuzzer:run/1` と `fuzzer:run/5` は、fuzzing 専用の BEAM で呼び出す。
libFuzzer が長時間 dirty CPU スケジューラーを 1 本占有するため、他の処理と同じ BEAM で動かさない。

`evaluate/1` が `crash` を返した場合、または fuzz target のプロセスが終了した場合、libFuzzer は BEAM 全体を abort させる。
このとき Erlang 側の後始末は行われない。

## rebar3_fuzzer

`rebar3_fuzzer` は、fuzz target を rebar3 から実行するためのプラグインである。
ソースコードは `rebar3_fuzzer/` にあり、詳細は `rebar3_fuzzer/README.md` を参照する。

```console
$ rebar3 fuzzer \
    --target example_fuzz_target \
    --runs 10000 \
    --max-length 4096
```

`--runs` の既定値は `0` であり、`0` はクラッシュ検出かユーザーの中断まで実行を続ける。
`--max-length` の既定値は `4096` である。

### オプション

| オプション | 説明 |
| --- | --- |
| `--target <module>` | fuzz target のモジュール名。必須 |
| `--runs <n>` | 実行回数。`0` は継続実行 |
| `--max-length <bytes>` | 入力の最大バイト数 |
| `--corpus <path>` | コーパスディレクトリー |
| `--artifacts <path>` | クラッシュ入力の保存先 |
| `--dict <path>` | libFuzzer の辞書ファイル |
| `--timeout <seconds>` | 1 入力あたりのタイムアウト秒 |
| `--max-total-time <seconds>` | fuzzing 全体の制限時間秒 |
| `--seed <value>` | 乱数シード |
| `--rss-limit-mb <mb>` | RSS の上限 (MB) |
| `--cover <modules>` | カンマ区切りのモジュール名。実行後にカバレッジを表示する |
| `--repro <path>` | artifact を再実行する。fuzzing は行わない |
| `--jobs <n>` | N 個の BEAM を並列起動し、終了後にコーパスと artifact をマージする |

`--jobs` は `--runs` が 1 以上の場合だけ使える。
`--workers` は未対応である。
`--repro` は `--target` と一緒に指定する。

`--target` に指定できるのは `^[a-z][a-zA-Z0-9_@]*$` に一致するモジュール名だけである。

### rebar.config での設定

オプションは `rebar.config` にも指定できる。
コマンドラインの指定が `rebar.config` より優先される。

```erlang
{fuzzer, [{target, example_fuzz_target},
          {runs, 0},
          {max_length, 4096},
          {corpus, "_build/fuzz/example/corpus"},
          {artifacts, "_build/fuzz/example/artifacts"},
          {dict, "fuzz/example.dict"},
          {timeout, 30},
          {max_total_time, 600},
          {seed, 1234},
          {rss_limit_mb, 4096},
          {cover, [example_fuzz_target, example_parser]}]}.
```

`--cover` の値はカンマ区切りの文字列であり、`rebar.config` ではモジュールのリストになる。

### 保存先

保存先を省略した場合、コーパスとクラッシュ入力を次のディレクトリーに保存する。

```text
_build/fuzz/<target>/
├── corpus/
└── artifacts/
```

ディレクトリーが存在しない場合は作成される。
保存先は `--corpus` と `--artifacts` で変更できる。

### 並列実行 (--jobs)

`--jobs N` は N 個の BEAM を並列起動する。
各ジョブはベースディレクトリー配下の `corpus/job-N` と `artifacts/job-N` を使う。
ベースコーパスの通常ファイルは各ジョブへ複製され、終了後にベースのコーパスと artifact へマージされる。

`--jobs` は `--runs` が 1 以上の場合だけ使える。
`--runs 0` との組み合わせはエラーになる。

### 再現

`--repro` を指定すると、fuzzing ではなく artifact の再実行を行う。

```console
$ rebar3 fuzzer \
    --target example_fuzz_target \
    --repro _build/fuzz/example/artifacts/crash-<SHA-1>
```

`--repro` の終了コードは次のとおり。

| 終了コード | 意味 |
| --- | --- |
| `0` | 再現に成功した (`OK: <Features>` を表示) |
| `1` | クラッシュを再現した (`CRASH: <Report>` を表示) |
| `2` | artifact を読めないなどのエラー |

### CI での利用

有限回の fuzzing を CI で回す場合は `--runs` を指定する。
クラッシュや異常終了ではプラグインが非ゼロで終了する。

```console
$ rebar3 fuzzer --target example_fuzz_target --runs 10000 --max-length 4096
```

`--repro` を使うと、保存済みの artifact を CI で再現できる。
クラッシュを再現した場合は終了コード `1`、artifact を読めない場合は `2` になる。

## コーパスと artifact

コーパスの各ファイルには、fuzz target へ渡すバイナリーをそのまま保存する。
libFuzzer は新しい feature を検出した入力をコーパスへ追加する。
対象の関数へ渡したいバイナリーを、コーパスディレクトリーへ直接配置できる。

## クラッシュレポート

`evaluate/1` が `crash` を返した場合、または例外を送出した場合、`artifacts` ディレクトリーへ libFuzzer の artifact と同じ SHA-1 を使ったレポートを書き出す。

```text
artifacts/
├── crash-<SHA-1>
└── crash-<SHA-1>.report
```

`crash-<SHA-1>` は libFuzzer が保存するクラッシュ入力である。
`crash-<SHA-1>.report` には次の情報が入る。

- `input_sha1`: 入力の SHA-1
- `input_size`: 入力のバイト数
- `reason`: 例外の種類と理由、または `target_returned_crash`、`{invalid_features, Features}`、`{invalid_return, Other}`、`{reset_failed, ...}`
- `stacktrace`: 例外のスタックトレース
- `timeout_ms`: タイムアウトの場合だけ入る

タイムアウトした場合は `reason => timeout` と `timeout_ms` が入る。
レポートの書き込みに失敗しても fuzzing は止めず、警告だけを出す。

ワーカープロセス自体が終了した場合は、レポートを書かずに BEAM を abort する。

## Erlang カバレッジ

`cover` オプションにモジュールのリストを指定すると、`cover` で Erlang カバレッジを計測する。

```erlang
fuzzer:run(#{target => example_fuzz_target,
             runs => 10000,
             corpus => "_build/fuzz/example/corpus",
             artifacts => "_build/fuzz/example/artifacts",
             cover => [example_fuzz_target, example_parser]}).
```

計測対象のモジュールは `+debug_info` 付きでコンパイルされている必要がある。
rebar3 の既定の設定では `debug_info` が付与される。

カバレッジは `coverage` キーに、モジュールごとの `covered`、`not_covered`、`total`、`percentage` として返る。

- `cover` サーバーがまだ起動していない場合はライブラリが起動し、実行後に停止する。
- すでに起動している場合は停止しない。
- クラッシュで BEAM 全体が終了した場合、カバレッジは返らない。
- このカバレッジは実行後の集計であり、libFuzzer の探索には使われない。

## NIF と Erlang ワーカー

NIF は `libclang_rt.fuzzer_no_main` を静的リンクし、dirty CPU スケジューラーで `LLVMFuzzerRunDriver` を実行する。
libFuzzer が入力を生成するたびに、NIF は通常スケジューラーで動作する Erlang ワーカーへバイナリーを送る。
Erlang ワーカーは fuzz target の `evaluate/1` を呼び出し、feature bitmap または `crash` を NIF へ返す。

NIF は feature bitmap の各 bit と、bitmap 全体のハッシュを libFuzzer のカウンターへ登録する。
これにより、bit の組み合わせも feature として扱われる。

同じ BEAM では、同時に 1 件の `fuzzer:run/1` だけを実行できる。
RTP と SDP の fuzzing を同時に実行する場合は、それぞれ別の BEAM を起動する。

## 制約と落とし穴

- libFuzzer が直接取得する coverage は NIF の coverage である。Erlang bytecode の分岐 coverage は自動収集されない。
- Erlang コードの状態は feature bitmap でしか通知できない。探索を制御したい状態は明示的に feature へ割り当てる。
- feature bitmap は 64 bit である。bit の組み合わせは 65,536 個のハッシュカウンターで表現するため、衝突の可能性がある。
- ワーカーは 1 個を使い回す。状態を持つ fuzz target は `reset/0` を実装する。
- BEAM 自体には ASan / UBSan を適用しない。
- fuzzing 中のクラッシュは BEAM 全体を abort させる。Erlang 側の後始末は行われない。
- `fuzzer:run/1` の `jobs` / `workers` は未対応である。並列実行は `rebar3_fuzzer --jobs` か別々の BEAM で行う。
- `fuzzer:run/1` と `fuzzer:run/5` は fuzzing 専用の BEAM で呼ぶ。
- 同じ BEAM で `fuzzer:run/1` を同時に実行すると `busy` 例外になる。
- Erlang カバレッジは `cover` を指定した場合だけ収集し、正常終了時にしか返らない。
- `fuzzer` と `rebar3_fuzzer` の Hex パッケージは未公開である。
- 入力タイムアウトは libFuzzer の `-timeout` ではなく Erlang の watchdog で監視する。libFuzzer の `-timeout` は BEAM のシグナル処理と競合するため、内部的に `-timeout=0` を指定している。
- `dict` は libFuzzer の辞書ファイルである。ファイルが存在しない場合は `error({invalid_option, ...})` になる。

## チェックリスト

### fuzz target を追加するとき

- `-behaviour(fuzzer_target)` と `evaluate/1` を実装したか。
- 通常の入力エラーを `crash` ではなく feature に割り当てたか。
- 探索してほしい分岐や状態を feature bitmap に割り当てたか。
- 状態を持つ場合に `reset/0` を実装したか。
- 外部 I/O、乱数、時刻に依存していないか。
- `evaluate/1` が 64 bit の範囲内の整数を返すか。

### 実行するとき

- fuzzing 専用の BEAM で実行しているか。
- 有限回で回す場合は `runs` を指定したか。
- `timeout` を指定する場合は秒単位であることを確認したか。
- `corpus` と `artifacts` の保存先を意図したディレクトリーにしたか。
- `--jobs` を使う場合に `--runs` が 1 以上か。
- クラッシュ時に artifact と `crash-<SHA-1>.report` を確認したか。

### クラッシュを再現するとき

- `fuzzer:reproduce/2` または `rebar3 fuzzer --repro` を使ったか。
- `--repro` の終了コード (`0` / `1` / `2`) を確認したか。
- 再現には `--target` を指定したか。
