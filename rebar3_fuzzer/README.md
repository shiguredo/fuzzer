# rebar3_fuzzer

`rebar3_fuzzer` は、`fuzzer` の fuzz target を rebar3 から実行するためのプラグインです。

`fuzzer` は Hex で `2026.1.0-canary.0` として公開しています。
`rebar3_fuzzer` はこのリポジトリに含まれるプラグインで、Hex では公開していません。

プロジェクトの `rebar.config` に次の設定を追加します。

```erlang
{deps, [{fuzzer, "2026.1.0-canary.0"}]}.

{project_plugins,
 [{rebar3_fuzzer,
   {git_subdir, "https://github.com/shiguredo/fuzzer.git",
    {branch, "develop"}, "rebar3_fuzzer"}}]}.
```

fuzz target を指定して fuzzing を実行します。

```console
$ rebar3 fuzzer --target example_fuzz_target
```

実行回数と入力の最大バイト数を指定できます。

```console
$ rebar3 fuzzer \
    --target example_fuzz_target \
    --runs 10000 \
    --max-length 4096
```

`--runs 0` は、クラッシュを検出するか、ユーザーが中断するまで実行を続けます。
`--runs` の既定値は `0`、`--max-length` の既定値は `4096` です。

次のオプションも指定できます。

| オプション | 説明 |
| --- | --- |
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
| `--jobs <n>` | N 個の BEAM を並列起動し、終了後にコーパスと artifact をマージする。`--runs` が 1 以上必要 |

`--repro` は `--target` と一緒に指定します。

```console
$ rebar3 fuzzer \
    --target example_fuzz_target \
    --repro _build/fuzz/example/artifacts/crash-<SHA-1>
```

`--jobs N` は N 個の BEAM を並列起動します。
各ジョブは `corpus/job-N` と `artifacts/job-N` を使い、終了後にベースのコーパスと artifact へマージされます。
`--jobs` は `--runs` が 1 以上の場合だけ使えます。
`--workers` は未対応です。

コーパスとクラッシュ入力の保存先も指定できます。

```console
$ rebar3 fuzzer \
    --target example_fuzz_target \
    --corpus _build/fuzz/example/corpus \
    --artifacts _build/fuzz/example/artifacts
```

保存先を省略した場合、次のディレクトリーを使用します。存在しない場合は作成されます。

```text
_build/fuzz/<target>/
├── corpus/
└── artifacts/
```

クラッシュした場合は、クラッシュ入力と一緒に `crash-<SHA-1>.report` が保存されます。
レポートには例外の種類、理由、スタックトレースが入ります。

`--cover` を指定した場合、`cover` で計測した Erlang カバレッジを実行後に表示します。
計測対象のモジュールは `+debug_info` 付きでコンパイルされている必要があります。

`--feedback` を指定した場合、Erlang コードの行または節の到達を libFuzzer の
探索に使います。`--feedback-mode` で計測単位を選びます。

- `line`: OTP の native coverage による行単位の計測
- `clause`: parse transform による節単位の計測

計測対象のモジュールは `+debug_info` 付きでコンパイルされている必要があります。
BEAM に `+JPcover` を付ける必要はありません。`--feedback` と `--cover` は
同時に指定できません。

`--auto-dict false` を指定すると、リテラルからの辞書の自動生成を止めます。
`--dict` を指定した場合、自動生成した辞書と利用者の辞書は 1 ファイルにまとめて
から使われます。`--dict-modules` を指定すると、target に加えてそのモジュールの
リテラルを辞書の生成元にします。

`--on-crash continue` を指定すると、クラッシュしても BEAM を終了せずに fuzzing を
続けます。クラッシュは `crash_id` で重複を除いて artifact に保存され、終了時に
検出したクラッシュの一覧が表示されます。タイムアウトした場合はワーカーを作り直して
続行します。クラッシュを 1 件でも検出した場合、終了コードは 0 ではありません。
既定値は `abort` です。

オプションは `rebar.config` にも指定できます。

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

`feedback` を使う場合は、`cover` の代わりに次のように指定します。

```erlang
{fuzzer, [{target, example_fuzz_target},
          {feedback, [example_parser]},
          {feedback_mode, line}]}.
```

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

libFuzzer のライセンスについては、リポジトリ直下の `THIRD_PARTY_LICENSES.md` を参照してください。
