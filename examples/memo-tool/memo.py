#!/usr/bin/env python3
"""業務メモ整理ツール memo-tool(完全ローカル動作。外部通信・削除機能を持たない)"""
import os
import ctypes
import errno
import stat
import sys
import time

MEMO_DIR = "memos"
ARCHIVE_DIR = "archive"


FAILED = False


def fail(msg):
    global FAILED
    FAILED = True
    print(msg, file=sys.stderr)


def open_safe_dir(path):
    """Open a real directory once so later operations cannot follow a swapped path."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise OSError(f"{path} を安全に開けません(シンボリックリンクは拒否): {error}") from error
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise OSError(f"{path} はディレクトリではありません")
    return descriptor


def iter_memo_files(directory_fd):
    """Yield opened regular .txt files without following directory-entry links."""
    for name in sorted(os.listdir(directory_fd)):
        if not name.endswith(".txt"):
            continue
        try:
            file_fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
        except OSError as error:
            fail(f"拒否(通常ファイルとして安全に開けません): {name}: {error}")
            continue
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            os.close(file_fd)
            fail(f"拒否(通常ファイルではありません): {name}")
            continue
        yield name, file_fd


def search(keyword):
    hits = 0
    directory_fd = open_safe_dir(MEMO_DIR)
    try:
        for name, file_fd in iter_memo_files(directory_fd):
            try:
                with os.fdopen(file_fd, encoding="utf-8") as f:
                    file_fd = -1
                    for i, line in enumerate(f, 1):
                        if keyword in line:
                            print(f"{name}:{i}: {line.rstrip(chr(10) + chr(13))}")
                            hits += 1
            except (OSError, UnicodeDecodeError) as e:
                fail(f"読み取り失敗: {name}: {e}")
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
    finally:
        os.close(directory_fd)
    print(f"該当 {hits} 行")


def rename_no_replace(source_dir_fd, source_name, destination_dir_fd, destination_name):
    """Atomically rename without replacing an existing destination (macOS/Linux)."""
    libc = ctypes.CDLL(None, use_errno=True)
    source = os.fsencode(source_name)
    destination = os.fsencode(destination_name)
    if hasattr(libc, "renameat2"):
        result = libc.renameat2(
            source_dir_fd, source, destination_dir_fd, destination, 1  # RENAME_NOREPLACE
        )
    elif hasattr(libc, "renameatx_np"):
        result = libc.renameatx_np(
            source_dir_fd, source, destination_dir_fd, destination, 4  # RENAME_EXCL
        )
    else:
        raise OSError(errno.ENOTSUP, "このOSは原子的な非上書き移動に対応していません")
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination_name)


def move_without_overwrite(name, source_fd, memo_dir_fd, archive_dir_fd):
    """Atomically move the same opened file without overwriting an existing memo."""
    source_identity = (os.fstat(source_fd).st_dev, os.fstat(source_fd).st_ino)
    base, ext = os.path.splitext(name)
    counter = 0
    while True:
        dest_name = name if counter == 0 else f"{base}.{counter}{ext}"
        try:
            current = os.stat(name, dir_fd=memo_dir_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != source_identity:
                raise OSError("移動前に元ファイルが差し替えられました")
            rename_no_replace(
                memo_dir_fd,
                name,
                archive_dir_fd,
                dest_name,
            )
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
            counter += 1
            continue
        break
    return dest_name


def archive(days):
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    memo_dir_fd = open_safe_dir(MEMO_DIR)
    archive_dir_fd = open_safe_dir(ARCHIVE_DIR)
    limit = time.time() - days * 86400
    moved = 0
    try:
        for name, file_fd in iter_memo_files(memo_dir_fd):
            try:
                if os.fstat(file_fd).st_mtime < limit:
                    dest_name = move_without_overwrite(
                        name, file_fd, memo_dir_fd, archive_dir_fd
                    )
                    moved += 1
                    print(f"移動しました: {name} -> {ARCHIVE_DIR}/{dest_name}")
            except OSError as e:
                fail(f"移動失敗: {name}: {e}")
            finally:
                os.close(file_fd)
    finally:
        os.close(memo_dir_fd)
        os.close(archive_dir_fd)
    print(f"移動 {moved} 件")


def main():
    if len(sys.argv) != 3:
        print("usage: memo.py search <keyword> | archive <days>")
        sys.exit(1)
    if not os.path.isdir(MEMO_DIR):
        print("memos/ フォルダがありません")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "search":
        if not sys.argv[2]:
            print("検索キーワードは空にできません")
            sys.exit(1)
        try:
            search(sys.argv[2])
        except OSError as error:
            print(error)
            sys.exit(1)
    elif cmd == "archive":
        try:
            days = int(sys.argv[2])
        except ValueError:
            print("日数は整数で指定してください")
            sys.exit(1)
        if days < 1 or days > 36500:
            print("日数は1〜36500の範囲で指定してください(事故防止)")
            sys.exit(1)
        try:
            archive(days)
        except OSError as error:
            print(error)
            sys.exit(1)
    else:
        print(f"unknown command: {cmd}")
        sys.exit(1)
    if FAILED:
        sys.exit(1)


if __name__ == "__main__":
    main()
