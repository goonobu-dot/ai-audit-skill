#!/usr/bin/env python3
"""Intentionally unsafe audit fixture. Never use as the application."""
import os
import sys
import time

MEMO_DIR = "memos"


def search(keyword):
    for name in os.listdir(MEMO_DIR):
        path = os.path.join(MEMO_DIR, name)
        if name.endswith(".txt"):
            with open(path, encoding="utf-8") as handle:
                for number, line in enumerate(handle, 1):
                    if keyword in line:
                        print(f"{name}:{number}: {line.rstrip()}")


def archive(days):
    limit = time.time() - days * 86400
    for name in os.listdir(MEMO_DIR):
        path = os.path.join(MEMO_DIR, name)
        if name.endswith(".txt") and os.path.getmtime(path) < limit:
            os.remove(path)  # INTENTIONAL DEFECT: violates the no-delete requirement.


if __name__ == "__main__":
    if sys.argv[1] == "search":
        search(sys.argv[2])
    else:
        archive(int(sys.argv[2]))
