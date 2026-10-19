# fuzzer の使い方

`fuzzer` は、Erlang で実装した関数を libFuzzer から実行するためのライブラリである。
libFuzzer は NIF に直接リンクし、入力の生成、コーパスの更新、クラッシュ入力の保存を担当する。
Erlang は libFuzzer が生成したバイナリーを受け取り、対象の関数を実行する。

このリポジトリには、RTP パーサーと SDP パーサーを fuzzing するサンプルが含まれる。
rebar3 から fuzzing を実行する `rebar3_fuzzer` も含まれる。
`fuzzer` は Hex で公開している。`rebar3_fuzzer` はこのリポジトリに含まれる。
リポジトリ自体のビルドとテストは `doc/DEVELOPMENT.md` を参照する。

## 動作環境

`fuzzer` の NIF をビルドするには、次のツールが必要になる。

- Erlang/OTP 29.1 以上
- rebar3
- Clang
- Clang と同じバージョンの compiler-rt (`libclang_rt.fuzzer_no_main`)

リポジトリのサンプルを実行する場合は、初期コーパスの変換に `xxd` も必要になる。

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

NIF に静的リンクされている libFuzzer のバージョンは、Erlang から確認できる。
この値は NIF をビルドした Clang のバージョンであり、compiler-rt に含まれる libFuzzer のバージョンに対応する。

```erlang
1> fuzzer:libfuzzer_version().
<<"22.1.6">>
```

`make toolchain-info` でも同じバージョンを表示する。
Clang を更新した場合は `make clean` を実行してから NIF を再ビルドする。

## 利用プロジェクトへの導入

`fuzzer` は Hex で `2026.1.0-canary.0` として公開している。
`rebar3_fuzzer` はこのリポジトリに含まれるプラグインで、Hex では公開していない。
両方を使う場合、利用するプロジェクトの `rebar.config` に次の設定を追加する。

```erlang
{deps, [{fuzzer, "2026.1.0-canary.0"}]}.

{project_plugins,
 [{rebar3_fuzzer,
   {git_subdir, "https://github.com/shiguredo/fuzzer.git",
    {branch, "develop"}, "rebar3_fuzzer"}}]}.
```

プラグインの詳細は `rebar3_fuzzer/README.md` を参照する。

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
    % 例外は捕捉せず fuzzer に渡す。クラッシュレポートに理由とスタックトレースが残る。
    case example_parser:decode(Data) of
        {ok, Value} ->
            {ok, success_features(Value)};
        {error, too_short} ->
            {ok, 1 bsl 0};
        {error, invalid_header} ->
            {ok, 1 bsl 1}
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

`evaluate/1` が例外を送出した場合もクラッシュとして扱われる。
例外を自分で catch して `crash` を返すと、クラッシュレポートに例外の理由と
スタックトレースが残らないため、捕捉せずに伝播させる。

パーサーが不正な入力を通常のエラーとして返した場合、その結果を feature に割り当てる。
通常の入力エラーを `crash` にすると、libFuzzer はその入力を直ちにクラッシュとして保存する。

### コールバック

fuzz target は次のコールバックを実装できる。

| コールバック | 呼び出しタイミング |
| --- | --- |
| `init/0` | ワーカーの最初の入力の直前。タイムアウトでワーカーを作り直した場合も、新しいワーカーの最初の入力の直前 |
| `reset/0` | 各入力の `evaluate/1` の直前 |
| `terminate/0` | ワーカーが stop で終了するとき。タイムアウトで kill された場合は呼ばれない |

ワーカーは fuzzing の間ずっと 1 個のプロセスを使い回す。
プロセス辞書や ETS などに状態を持つ fuzz target は、`reset/0` で状態を初期化する。
`init/0` はワーカーの作り直しで複数回呼ばれうるため、名前付き ETS やプロセス登録を
行う場合は 2 回目以降も成功するように冪等にする。

### feature bitmap の設計

`Features` の各 bit には、fuzz target が到達した意味的な状態を割り当てる。
同じ入力で複数の状態へ到達した場合は、対応する bit を `bor` で結合する。

- 例外、`{ok, Features}` 以外の戻り値、64 bit の範囲外の feature はクラッシュ扱いになる。
- NIF は feature bitmap の各 bit と bitmap 全体のハッシュを libFuzzer のカウンターへ登録する。
- ハッシュ用のカウンターは 4,096 個に集約しているため、bit の組み合わせが衝突する可能性がある。
  この数を増やすと衝突は減るが、libFuzzer が入力ごとに走査するコストが増える。
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
  coverage => undefined | #{module() => #{covered => ..., ...}},
  crashes => [#{crash_id => ..., input_sha1 => ..., ...}]}
```

`coverage` は `cover` オプションを指定した場合だけマップになる。
`crashes` は `on_crash => continue` のときに検出した、重複を除いたクラッシュの一覧である。
`on_crash => abort` ではクラッシュ時にこの関数が戻らないため、通常は空リストになる。
`exit_code` は libFuzzer の終了コードであり、`continue` でクラッシュを検出しても 0 に
なることがある。CLI は `crashes` が空でない場合に終了コード 1 へ変換する。

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
| `feedback` | `[module()] \| #{modules := [module()], mode => line \| clause}` | `[]` | libFuzzer の探索に使う Erlang カバレッジ。リストは `line` の省略形 |
| `auto_dict` | `boolean()` | `true` | target と feedback のモジュールから辞書を自動生成する |
| `dict_modules` | `[module()]` | `[]` | 自動辞書の生成元に target と一緒に使うモジュール。空なら target と feedback を使う |
| `on_crash` | `abort \| continue` | `abort` | クラッシュ後の動作。`continue` は同じ BEAM で継続する |
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

### クラッシュ後の継続

`on_crash => continue` を指定すると、クラッシュした入力を受け取っても BEAM を終了せず、
fuzzing を続ける。クラッシュした入力は libFuzzer のコーパスには追加されない。

```erlang
fuzzer:run(#{target => example_fuzz_target,
             runs => 100000,
             on_crash => continue}).
```

- クラッシュは `crash_id` で重複を除き、初めて見る `crash_id` の入力だけを artifact と
  レポートに残す。
- `crash_id` は例外の種類、理由のタグ、`function_clause` のアリティ、OTP 外の最初の
  スタックトレースフレーム (行番号を含む) から作る。同じ関数の別の行で起きた
  クラッシュは別のものとして残す。
- タイムアウトした場合は、その入力のワーカーを kill して作り直し、fuzzing を続ける。
- タイムアウト以外の理由でワーカーが落ちた場合は、`continue` でも BEAM を abort する。
- 終了時に、重複を除いたクラッシュの一覧を `crashes` キーで返す。
- `rebar3_fuzzer` と `fuzzer_cli` は、`crashes` が空でなければ libFuzzer の終了コードが
  0 でも終了コード 1 で終わる。

`on_crash => abort` は従来どおり、クラッシュ時に BEAM 全体を終了する。

### 辞書の自動生成

`auto_dict` が `true` の場合、target と `feedback` に指定したモジュールの
abstract code から、binary、文字列、整数のリテラルを取り出して libFuzzer の
辞書を自動生成する。`debug_info` がないモジュールでは、BEAM の literal chunk
から取り出せる分だけを使う。

`dict_modules` を指定すると、target に加えてそのモジュールを辞書の生成元にする。
`feedback` を使わないパーサーなど、target 以外のモジュールにマジックナンバーが
ある場合は `dict_modules` で指定する。

binary の中の型指定のない文字列は latin1 のバイト列として扱う。`/utf8` が付いた
文字列だけを UTF-8 にする。整数は 2/3/4/8 バイトの big-endian と little-endian の
両方で出力する。STUN の magic cookie のような固定値は、この辞書によって探索の
手がかりになる。辞書は最大 4,096 エントリー、1 エントリーあたり最大 64 バイトに
制限している。上限を超える場合は、パターン、ガード、比較の中のリテラルを優先する。
生成したエントリーが 0 件の場合は警告をログへ出す。

`dict` オプションで利用者の辞書を指定した場合、自動生成したエントリーと
1 つのファイルへまとめてから libFuzzer へ渡す。libFuzzer の `-dict` は
最後の 1 個しか有効にならないためである。

自動生成を止める場合は `auto_dict => false` を指定する。
自動生成した辞書の一時ファイルはシステムの一時ディレクトリーに置くため、
abort で BEAM が落ちても artifacts ディレクトリーには残らない。

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
| `--feedback <modules>` | カンマ区切りのモジュール名。コードカバレッジを libFuzzer の探索に使う |
| `--feedback-mode <mode>` | `line` / `clause`。既定値は `line` |
| `--auto-dict <true\|false>` | リテラルから辞書を自動生成する。既定値は `true` |
| `--dict-modules <modules>` | 自動辞書の生成元に target と一緒に使うモジュール (カンマ区切り) |
| `--on-crash <mode>` | `abort` / `continue`。既定値は `abort` |
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
          {auto_dict, true},
          {dict_modules, [example_parser]},
          {on_crash, abort},
          {cover, [example_fuzz_target, example_parser]}]}.
```

`--cover` の値はカンマ区切りの文字列であり、`rebar.config` ではモジュールのリストになる。
`--feedback` も同じ形式で、`--feedback-mode` で計測単位を指定する。
`feedback` と `cover` は同時に指定できない。

```erlang
{fuzzer, [{target, example_fuzz_target},
          {feedback, [example_parser]},
          {feedback_mode, line}]}.
```

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

`crash-<SHA-1>` はクラッシュ入力である。
`on_crash => abort` では libFuzzer が保存し、`on_crash => continue` では fuzzer 自身が保存する。
`on_crash => continue` では、同じ `crash_id` の入力は重複して保存しない。

`crash-<SHA-1>.report` には次の情報が入る。

- `input_sha1`: 入力の SHA-1
- `input_size`: 入力のバイト数
- `reason`: 例外の種類と理由、または `target_returned_crash`、`{invalid_features, Features}`、`{invalid_return, Other}`、`{reset_failed, ...}`、`{feedback_failure, Reason}`
- `stacktrace`: 例外のスタックトレース
- `crash_id`: クラッシュの同一性を表すマップ
- `timeout_ms`: タイムアウトの場合だけ入る

タイムアウトした場合は `reason => timeout` と `timeout_ms` が入る。
`feedback_failure` は target のクラッシュではなく、feedback のセットアップや
カウンター読み出しの失敗である。`--repro` は feedback をセットアップしないため、
同じ理由では再現しないことがある。

`crash_id` は、同じ原因のクラッシュを同じものとして扱うための識別子である。
次の情報を持つ。

- `class`: 例外の種類 (`error` / `exit` / `throw`)。例外以外のクラッシュでは `crash`
- `reason`: 例外の理由のタグ。タプルなら先頭の atom、atom ならその atom、それ以外は `other`
- `reason_arity`: `function_clause` の引数の数。VM が理由をアトムで返す場合はフレームのアリティを使う。それ以外は `undefined`
- `frame`: スタックトレースを先頭から見て、OTP のモジュールを除いた最初のフレーム。`{Module, Function, Arity, Line}` 形式。行番号が取れない場合は `0`

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
  探索に使う場合は、次のフィードバックカバレッジを使う。

## フィードバックカバレッジ

`feedback` オプションにモジュールのリストを指定すると、そのモジュールの行または節の
到達を libFuzzer の feature として入力ごとに渡す。feature bitmap だけでは探索が
進まないパーサーでも、コードの到達を手がかりに探索できる。

```erlang
fuzzer:run(#{target => example_fuzz_target,
             runs => 100000,
             feedback => [example_parser]}).
```

モジュールのリストは行単位の計測 (`line`) の省略形である。節単位を指定する
場合は、モジュールとモードを持つマップを渡す。

```erlang
fuzzer:run(#{target => example_fuzz_target,
             feedback => #{modules => [example_parser], mode => clause}}).
```

| モード | 計測単位 | 仕組み |
| --- | --- | --- |
| `line` | 行 | OTP の native coverage (`line_counters`) |
| `clause` | 節 | parse transform で全節の本体先頭に計測呼び出しを挿入 |

- `feedback` は計測対象のモジュールを計測用にコンパイルし直し、実行中のコードを
  置き換える。
- `line` は JIT の native coverage を使うため、`code:coverage_support/0` が
  `true` を返す環境が必要になる。OTP 29.1 以上では常に `true` になる。
- BEAM の起動時に `+JPcover` を付ける必要はない。`fuzzer` が
  `code:set_coverage_mode(line_counters)` で計測用のモードへ切り替える。
- `clause` は `debug_info` 付きの beam ファイルから abstract code を取り出し、
  全節の本体先頭に計測呼び出しを挿入して再コンパイルする。
- 再コンパイルでは、元の beam の `compile_info` から `export_all`、`tuple_calls`、
  `{feature, _, enable | disable}` を引き継ぐ。
- 計測対象のモジュールは `+debug_info` 付きでコンパイルされている必要がある。
  rebar3 の既定の設定では `debug_info` が付与される。
- fuzzing が終わると、計測対象のモジュールと coverage mode は元へ戻る。
- モジュールは `code:which/1` が返す beam ファイルから読み込む。コードパス上に
  実ファイルとして存在しないモジュールは指定できない。
- fuzzing 中に計測対象のモジュールをリロードしないこと。行の並びが変わった場合は
  入力の評価時にエラーになる。

`feedback` は `cover` と同時に指定できない。`cover` は実行後の集計のために
モジュールをロードし直すため、`feedback` の計測用コードと競合する。

同じ BEAM で feedback 付きの `fuzzer:run/1` を同時に呼ぶと、2 件目は
`error({feedback, already_running})` で失敗する。

### カウンターと性能

NIF は行と節のカウンターを 1 バイトずつ libFuzzer のカウンターへコピーする。
libFuzzer はカウンターを `1`, `2`, `3`, `4-7`, ... の段階に分けて feature にするため、
同じ行や節を何度も通る入力にも意味がある。

1 入力あたりのコストは、計測対象の行数と節数に比例する。

- 行カウンターは入力ごとに `code:get_coverage/2` で全行を読み、`code:reset_coverage/1`
  で 0 に戻す。
- 節カウンターは入力ごとに `atomics` から全節を読み出し、同時に 0 に戻す。
- 登録できるカウンターの上限は `fuzzer:max_feedback_counters/0` で確認できる。
  上限を超える場合は `feedback` のセットアップが失敗する。

対象を絞らずに大量のモジュールを指定すると、1 入力あたりのコストが大きくなる。
まずは探索に効かせたいパーサーのモジュールだけを指定する。

libFuzzer の `-print_coverage` は、NIF が登録するダミーの PC テーブルを使うため
Erlang の行番号を表示しない。実行中の `cov:` と `ft:` の数字には、行と節の到達が
反映される。

### 節カバレッジの範囲

`clause` モードは、関数、`case`、`if`、`receive`、`try`、`fun`、`maybe` の節の
本体先頭を計測する。`receive` の `after` 本体も 1 個の分岐として計測する。
ガードの各条件や `andalso` / `orelse` の短絡評価は節単位では区別しない。
行単位の違いが必要な場合は `line` を使う。

同じ行に複数の節がある場合、`line` モードはその行を 1 個のカウンターとして扱うため、
どの節を通ったかを区別できない。`clause` モードは節ごとにカウンターを持つため、
同じ行の分岐も探索の手がかりにできる。

## NIF と Erlang ワーカー

NIF は `libclang_rt.fuzzer_no_main` を静的リンクし、dirty CPU スケジューラーで `LLVMFuzzerRunDriver` を実行する。
libFuzzer が入力を生成するたびに、NIF は通常スケジューラーで動作する Erlang ワーカーへバイナリーを送る。
Erlang ワーカーは fuzz target の `evaluate/1` を呼び出し、feature bitmap または `crash` を NIF へ返す。

NIF は feature bitmap の各 bit と、bitmap 全体のハッシュを libFuzzer のカウンターへ登録する。
これにより、bit の組み合わせも feature として扱われる。
`feedback` を指定した場合は、Erlang 側で読み出した行・節のカウンターも NIF が
libFuzzer のカウンターへコピーする。

同じ BEAM では、同時に 1 件の `fuzzer:run/1` だけを実行できる。
RTP と SDP の fuzzing を同時に実行する場合は、それぞれ別の BEAM を起動する。

## 制約と落とし穴

- libFuzzer が直接取得する coverage は NIF の coverage である。Erlang コードの行・節の到達は `feedback` を指定した場合だけ探索に使われる。
- `feedback` と `cover` は同時に指定できない。
- `feedback` の計測対象は fuzzing 中にリロードしてはならない。
- `feedback` の 1 入力あたりのコストは行数と節数に比例する。上限は `fuzzer:max_feedback_counters/0` で確認できる。
- Erlang コードの状態は feature bitmap でしか通知できない。探索を制御したい状態は明示的に feature へ割り当てる。
- feature bitmap は 64 bit である。bit の組み合わせは 4,096 個のハッシュカウンターで表現するため、衝突の可能性がある。個々の bit も別のカウンターとして登録される。
- ワーカーは 1 個を使い回す。状態を持つ fuzz target は `reset/0` を実装する。
- BEAM 自体には ASan / UBSan を適用しない。
- fuzzing 中のクラッシュは BEAM 全体を abort させる。Erlang 側の後始末は行われない。
- `fuzzer:run/1` の `jobs` / `workers` は未対応である。並列実行は `rebar3_fuzzer --jobs` か別々の BEAM で行う。
- `fuzzer:run/1` と `fuzzer:run/5` は fuzzing 専用の BEAM で呼ぶ。
- 同じ BEAM で `fuzzer:run/1` を同時に実行すると `busy` 例外になる。
- Erlang カバレッジは `cover` を指定した場合だけ収集し、正常終了時にしか返らない。
- `fuzzer` は Hex で公開済みである。`rebar3_fuzzer` は Hex では未公開である。
- 入力タイムアウトは libFuzzer の `-timeout` ではなく Erlang の watchdog で監視する。libFuzzer の `-timeout` は BEAM のシグナル処理と競合するため、内部的に `-timeout=0` を指定している。
- `dict` は libFuzzer の辞書ファイルである。ファイルが存在しない場合は `error({invalid_option, ...})` になる。

## チェックリスト

### fuzz target を追加するとき

- `-behaviour(fuzzer_target)` と `evaluate/1` を実装したか。
- 通常の入力エラーを `crash` ではなく feature に割り当てたか。
- 探索してほしい分岐や状態を feature bitmap に割り当てたか。
- コードカバレッジを探索に使う場合、`feedback` に対象モジュールを指定したか。
- 状態を持つ場合に `reset/0` を実装したか。
- 外部 I/O、乱数、時刻に依存していないか。
- `evaluate/1` が 64 bit の範囲内の整数を返すか。

### 実行するとき

- fuzzing 専用の BEAM で実行しているか。
- 有限回で回す場合は `runs` を指定したか。
- `timeout` を指定する場合は秒単位であることを確認したか。
- `feedback` と `cover` を同時に指定していないか。
- `feedback` の対象モジュールが `+debug_info` 付きでコンパイルされているか。
- `corpus` と `artifacts` の保存先を意図したディレクトリーにしたか。
- `--jobs` を使う場合に `--runs` が 1 以上か。
- クラッシュ時に artifact と `crash-<SHA-1>.report` を確認したか。

### クラッシュを再現するとき

- `fuzzer:reproduce/2` または `rebar3 fuzzer --repro` を使ったか。
- `--repro` の終了コード (`0` / `1` / `2`) を確認したか。
- 再現には `--target` を指定したか。
