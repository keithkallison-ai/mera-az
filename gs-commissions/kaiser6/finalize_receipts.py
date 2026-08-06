#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Insert public_commit into the six kaiser6 commission receipts, in BOTH locations
(working dir + published dir), preserving key order (public_commit sits directly
after public_repository, per the commission's receipt template)."""

import json
import os
import sys

LOCATIONS = [
    "C:/Temp/gs_commission_kaiser6",
    "C:/Temp/mera-az-deploy/gs-commissions/kaiser6",
]


def main():
    if len(sys.argv) != 2:
        print("usage: finalize_receipts.py <public_commit_sha>")
        return 2
    sha = sys.argv[1].strip()
    if not sha:
        print("empty sha refused")
        return 2
    changed = []
    for d in LOCATIONS:
        if not os.path.isdir(d):
            print("skip (absent): %s" % d)
            continue
        for fn in sorted(os.listdir(d)):
            if not (fn.startswith("commission_") and fn.endswith("_receipt.json")):
                continue
            p = os.path.join(d, fn)
            with open(p, encoding="utf-8") as f:
                obj = json.load(f)
            out = {}
            for k, v in obj.items():
                if k == "public_commit":
                    continue
                out[k] = v
                if k == "public_repository":
                    out["public_commit"] = sha
            if "public_commit" not in out:
                out["public_commit"] = sha
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
                f.write("\n")
            changed.append(p)
    print("updated %d receipt files with public_commit=%s" % (len(changed), sha))
    for p in changed:
        print("  " + p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
