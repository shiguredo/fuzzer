# CHANGES

## develop

- [ADD] `--dict`、`--timeout`、`--max-total-time`、`--seed`、`--rss-limit-mb`、`--cover` を追加する
  - @voluntas
- [ADD] `--repro` で artifact を再実行できるようにする
  - @voluntas
- [ADD] `--jobs` で複数 BEAM を並列実行し、コーパスと artifact をマージする
  - @voluntas
- [FIX] 再現モードの eval 文字列を base64 経由にしてシェル引用符の問題を避ける
  - @voluntas
