#!/usr/bin/env python3
"""Renumber duplicate project dirs to eliminate collisions."""

import os
import shutil
from pathlib import Path

HIVE = Path("/home/kirk/.picoclaw/workspace/Hivemind-projects")

# (old, new) -- second dir in each collision pair
renumbers = [
    ("66-software-supply-chain",   "73-software-supply-chain"),
    ("67-container-security",      "74-container-security"),
    ("68-bug-bounty-playbook",     "75-bug-bounty-playbook"),
    ("69-steganography",          "71-steganography"),
    ("70-biometric-auth",         "72-biometric-auth"),
]

for old, new in renumbers:
    old_path = HIVE / old
    new_path = HIVE / new

    if not old_path.exists():
        print(f" SKIP: {old} does not exist")
        continue

    if new_path.exists():
        print(f" SKIP: {new} already exists")
        continue

    # Rename
    shutil.move(str(old_path), str(new_path))
    print(f" RENAME: {old} -> {new}")

print("Done.")
