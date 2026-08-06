#!/usr/bin/env python3
"""業務メモ整理ツール memo-tool(完全ローカル動作。外部通信・削除機能を持たない)"""
import os
import shutil
import sys
import time

MEMO_DIR = "memos"
ARCHIVE_DIR = "archive"


FAILED = False


def fail(msg):
    global FAILED
    FAILED = True
    print(msg, file=sys.stderr)


def check_dir_safety(d):
    """基準ディレクトリ自体がシンボリックリンクなら拒否(領域外への逸脱防止)"""
    if os.path.islink(d):
        print(f"{d} がシンボリックリンクのため処理を中止します")
        sys.exit(1)


def iter_memo_files():
    """memos/ 直下の通常ファイルの .txt のみを対象にする(シンボリックリンクは除外)"""
    check_dir_safety(MEMO_DIR)
    for name in sorted(os.listdir(MEMO_DIR)):
        path = os.path.join(MEMO_DIR, name)
        if not name.endswith(".txt"):
            continue
        if os.path.islink(path) or not os.path.isfile(path):
            print(f"スキップ(通常ファイルではありません): {name}", file=sys.stderr)
            continue
        yield name, path


def search(keyword):
    hits = 0
    for name, path in iter_memo_files():
        try:
            with open(path, encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    if keyword in line:
                        print(f"{name}:{i}: {line.rstrip()}")
                        hits += 1
        except (OSError, UnicodeDecodeError) as e:
            fail(f"読み取り失敗: {name}: {e}")
    print(f"該当 {hits} 行")


def archive(days):
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    check_dir_safety(ARCHIVE_DIR)
    limit = time.time() - days * 86400
    moved = 0
    for name, path in iter_memo_files():
        try:
            if os.path.getmtime(path) < limit:
                base, ext = os.path.splitext(name)
                dest_name = name
                n = 1
                while True:
                    dest = os.path.join(ARCHIVE_DIR, dest_name)
                    try:
                        fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                        os.close(fd)
                        break
                    except FileExistsError:
                        dest_name = f"{base}.{n}{ext}"
                        n += 1
                os.replace(path, dest)
                moved += 1
                print(f"移動しました: {name} -> {ARCHIVE_DIR}/{dest_name}")
        except OSError as e:
            fail(f"移動失敗: {name}: {e}")
    print(f"移動 {moved} 件")


def main():
    if len(sys.argv) < 3:
        print("usage: memo.py search <keyword> | archive <days>")
        sys.exit(1)
    if not os.path.isdir(MEMO_DIR):
        print("memos/ フォルダがありません")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "search":
        search(sys.argv[2])
    elif cmd == "archive":
        try:
            days = int(sys.argv[2])
        except ValueError:
            print("日数は整数で指定してください")
            sys.exit(1)
        if days < 1 or days > 36500:
            print("日数は1〜36500の範囲で指定してください(事故防止)")
            sys.exit(1)
        archive(days)
    else:
        print(f"unknown command: {cmd}")
        sys.exit(1)
    if FAILED:
        sys.exit(1)


if __name__ == "__main__":
    main()
