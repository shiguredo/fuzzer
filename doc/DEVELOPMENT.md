# 開発

リポジトリのビルド、テスト、サンプル、Hex パッケージについてまとめる。
ライブラリとしての使い方は `doc/USAGE.md` を参照する。

## リポジトリでのビルドとテスト

Erlang モジュールと NIF をビルドする。

```console
$ make compile
```

EUnit を実行する。

```console
$ make test
```

efmt、elint、clang-format を prek 経由で実行する。prek が必要になる。

```console
$ make lint
```

Git フックを有効にする場合は、リポジトリ直下で次を実行する。

```console
$ prek install --prepare-hooks
```

生成物を削除する。

```console
$ make clean
```

## サンプルの実行

RTP サンプルは、[RFC 3550](https://www.rfc-editor.org/rfc/rfc3550.html) の固定ヘッダー、CSRC、header extension、padding を解析する。
SDP サンプルは、[RFC 8866](https://www.rfc-editor.org/rfc/rfc8866.html) の行構造と必須フィールドを解析する。

RTP と SDP の fuzzing をそれぞれ 10,000 回実行する。

```console
$ make fuzz-smoke
```

RTP の fuzzing を継続実行する。

```console
$ make fuzz-rtp
```

SDP の fuzzing を継続実行する。

```console
$ make fuzz-sdp
```

`make fuzz-rtp` と `make fuzz-sdp` は、クラッシュを検出するか、ユーザーが中断するまで実行を続ける。
`make fuzz-rtp` は `max_length` に 2048、`make fuzz-sdp` は 16384 を指定している。

サンプルごとのコーパスとクラッシュ入力は、次のディレクトリーに保存される。

```text
_build/fuzz/
├── rtp/
│   ├── corpus/
│   └── artifacts/
└── sdp/
    ├── corpus/
    └── artifacts/
```

## 初期コーパス

RTP と SDP の初期コーパスは、レビューしやすいように 16 進文字列で管理している。
Makefile は `xxd -r -p` を使い、fuzzing の開始前にバイナリーファイルへ変換する。

```text
examples/
├── rtp/corpus/
│   ├── extension.hex
│   ├── minimal.hex
│   └── padding.hex
└── sdp/corpus/
    ├── media.hex
    └── minimal.hex
```

## バージョン

`fuzzer` アプリケーションのバージョンは、リポジトリ直下の `VERSION` を唯一の情報源とする。
`src/fuzzer.app.src` の `vsn` はビルド時に `VERSION` の内容を読み込むため、バージョンを上げるときは `VERSION` だけを更新する。

`rebar3_fuzzer` は独立したバージョンで管理しており、`rebar3_fuzzer/src/rebar3_fuzzer.app.src` の `vsn` で指定する。

NIF に静的リンクする libFuzzer のバージョンは、ビルドに使う Clang のバージョンから `Makefile` が決定し、NIF へ埋め込む。
`fuzzer:libfuzzer_version/0` と `make toolchain-info` で確認できる。
Clang を更新した場合は `make clean` を実行してから NIF を再ビルドする。

### canary リリース

canary リリースでは `canary.py` を使う。`develop` ブランチで実行する。

```console
$ python3 canary.py
```

`canary.py` は `VERSION` の canary の連番を 1 つ進め、`VERSION` だけをコミットし、新しいバージョン名のタグを作成して `develop` とタグを `origin` へ push する。

実行内容だけを確認したい場合は `--dry-run` を付ける。

```console
$ python3 canary.py --dry-run
```

バージョンは日付ベースの CalVer に canary の連番を付けた形式である。

```text
2026.1.0-canary.0
2026.1.0-canary.1
2026.1.0
2026.2.0-canary.0
```

canary が付いている間はベースのバージョンを変えずに連番だけを進める。canary が付いていないリリース済みの `VERSION` から実行した場合は、次のリリースの `canary.0` を開始する。

`rebar3_fuzzer` のバージョンは `canary.py` では更新しない。

## Hex パッケージ

`fuzzer` と `rebar3_fuzzer` は Hex パッケージとしてビルドできる。

```console
$ rebar3 hex build
$ cd rebar3_fuzzer && rebar3 hex build
```

Hex へ公開する場合は、Hex の API キーを設定したうえで `rebar3 hex publish` を実行する。
`fuzzer` は `2026.1.0-canary.0` を Hex で公開済みである。
`rebar3_fuzzer` はまだ公開していない。
