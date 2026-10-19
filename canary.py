"""fuzzer の canary バージョンを上げるスクリプト。

リポジトリ直下の VERSION だけを更新し、同じ名前の git タグを作成して
develop ブランチとタグを origin へ push する。
rebar3_fuzzer は独立したバージョンで管理しているため、このスクリプトでは触らない。
"""

import argparse
import re
import subprocess
import sys
from typing import NoReturn

__all__ = ["increment_version", "main"]

# fuzzer アプリケーションのバージョンの唯一の情報源
VERSION_FILE: str = "VERSION"

# canary リリースを打つブランチ
RELEASE_BRANCH: str = "develop"

# fuzzer のバージョンは日付ベースの CalVer (YYYY.M.PATCH) に canary の連番を付ける。
# canary の例: 2026.1.0-canary.0, 2026.1.0-canary.1, ...
# リリースの例: 2026.1.0
VERSION_PATTERN: re.Pattern[str] = re.compile(
    r"(?P<year>\d{4})\.(?P<release>\d+)\.(?P<patch>\d+)"
    r"(?:-canary\.(?P<canary>\d+))?"
)

# コミットメッセージは shiguredo-git の規約に合わせて日本語の命令形にする
COMMIT_MESSAGE: str = "バージョンを上げる"


def increment_version(current_version: str) -> str:
    """canary の連番を 1 つ進めたバージョンを返す。

    canary が付いていないリリース済みのバージョンからは、次のリリースの
    canary.0 を開始する。
    """
    match = VERSION_PATTERN.fullmatch(current_version)
    if match is None:
        raise ValueError(
            f"Invalid version format: {current_version!r} "
            "(expected YYYY.M.PATCH or YYYY.M.PATCH-canary.N)"
        )

    year = match.group("year")
    release = match.group("release")
    patch = match.group("patch")
    canary = match.group("canary")

    if canary is None:
        # リリース済みのバージョンから次のリリースの canary を開始する
        return f"{year}.{int(release) + 1}.0-canary.0"

    # canary の連番だけを進め、ベースのバージョンは変えない
    return f"{year}.{release}.{patch}-canary.{int(canary) + 1}"


def confirm_update(current_version: str, new_version: str) -> bool:
    """バージョンを更新してよいかユーザーに確認する。"""
    response = input(f"Update version from {current_version} to {new_version}? (y/n): ")
    return response.strip().lower() == "y"


def run_git(*args: str) -> str:
    """git コマンドを実行し、標準出力を返す。

    失敗した場合は CalledProcessError を送出して、以降の処理を止める。
    """
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def current_branch() -> str:
    """現在のブランチ名を返す。"""
    return run_git("rev-parse", "--abbrev-ref", "HEAD")


def tag_exists(tag: str) -> bool:
    """指定した名前のタグが既に存在するかを返す。"""
    result = subprocess.run(
        ["git", "rev-parse", "--quiet", "--verify", f"refs/tags/{tag}"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def update_version_and_tag(dry_run: bool) -> None:
    """VERSION を更新し、コミット、タグ作成、push までを行う。"""
    branch = current_branch()
    if branch != RELEASE_BRANCH:
        print(
            f"This script should be run on the {RELEASE_BRANCH!r} branch "
            f"(current branch: {branch!r})",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(VERSION_FILE, "r", encoding="utf-8") as file:
        current_version = file.read().strip()

    new_version = increment_version(current_version)

    if tag_exists(new_version):
        print(f"Tag {new_version} already exists.", file=sys.stderr)
        sys.exit(1)

    if dry_run:
        print(
            f"Dry run: {VERSION_FILE} would be updated "
            f"from {current_version} to {new_version}"
        )
        print(f"Dry run: git commit -m '{COMMIT_MESSAGE}' would be executed")
        print(f"Dry run: git tag {new_version} would be executed")
        print(f"Dry run: git push origin {RELEASE_BRANCH} would be executed")
        print(f"Dry run: git push origin {new_version} would be executed")
        return

    if not confirm_update(current_version, new_version):
        print("Update cancelled.")
        return

    # prek の end-of-file-fixer に合わせて末尾へ改行を 1 つ入れる。
    # 改行が無いとフックがファイルを書き換えてコミットに失敗するため。
    with open(VERSION_FILE, "w", encoding="utf-8") as file:
        file.write(new_version + "\n")

    # VERSION だけをコミットし、作業中の他の変更を巻き込まない
    run_git("add", VERSION_FILE)
    run_git("commit", "-m", COMMIT_MESSAGE)

    # タグを打ってから develop とタグを push する。
    # develop を先に push し、タグが指すコミットをリモートに存在させる。
    run_git("tag", new_version)
    run_git("push", "origin", RELEASE_BRANCH)
    run_git("push", "origin", new_version)

    print(f"Version updated from {current_version} to {new_version}.")


def main() -> NoReturn:
    """コマンドライン引数を解析して canary バージョンの更新を実行する。"""
    parser = argparse.ArgumentParser(
        description="Update VERSION file and git tag for canary releases."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making any changes",
    )
    args = parser.parse_args()

    try:
        update_version_and_tag(dry_run=args.dry_run)
    except ValueError as error:
        print(error, file=sys.stderr)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
