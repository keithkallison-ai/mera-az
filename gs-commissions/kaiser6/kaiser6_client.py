#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
kaiser6 clean-room commission — six-source wire recovery client.

Written from the commission spec alone (clean room; Python stdlib only).

The ONLY data inputs are two HTTP routes on the local serve:
    GET http://127.0.0.1:8821/api/manifest
    GET http://127.0.0.1:8821/api/source/<tag16>   (tag16 = first 16 hex chars of member_sha256)

The client holds NOTHING local: every pin (member_sha256, member_bytes) is taken
from the wire manifest. Each of the six sources is recovered sequentially (never
in parallel), streamed in 4 MB chunks, sha256 folded on the fly (no document is
ever buffered; the largest is ~10.4 GB), bytes counted.

GREEN per source = streamed sha256 == wire member_sha256
                   AND byte count == wire member_bytes
                   AND tripwires 0/0.

ENFORCED INPUT CLOSURE (armed before the first data read):
  - builtins.open / io.open / os.open RAISE on any path outside
    C:/Temp/gs_commission_kaiser6/ (attempts recorded in tripwire_read_attempts)
  - a sys.meta_path hook RAISES on any module whose origin lies under
    C:/Users/keith/Payer (attempts recorded in tripwire_import_attempts)
HTTP is the only data channel. Both tripwire lists must end empty.
"""

import sys
import os
import io
import builtins
import json
import time
import uuid
import hashlib
import datetime
import http.client

WORK_ROOT = "C:/Temp/gs_commission_kaiser6"
ALLOWED_ROOT = os.path.normcase(os.path.abspath(WORK_ROOT))
FORBIDDEN_IMPORT_ROOT = os.path.normcase(os.path.abspath("C:/Users/keith/Payer"))

HOST = "127.0.0.1"
PORT = 8821
CHUNK = 4 * 1024 * 1024  # 4 MB per commission spec
REQUIRED_IDS = ["kfhp-co", "knew-co20", "knew-ga01", "knew-hi01", "knew-ma01", "k-nc"]
PUBLIC_REPOSITORY = "https://github.com/keithkallison-ai/mera-az"

SESSION_ID = str(uuid.uuid4())  # one uuid minted at start, identical across the six receipts

tripwire_read_attempts = []
tripwire_import_attempts = []

_real_open = builtins.open
_real_os_open = os.open


def _decode_path(p):
    """Best-effort absolute+normcased string form of a path-like; None if not decodable."""
    try:
        if hasattr(p, "__fspath__"):
            p = os.fspath(p)
        if isinstance(p, bytes):
            p = os.fsdecode(p)
        if not isinstance(p, str):
            return None
        return os.path.normcase(os.path.abspath(p))
    except Exception:
        return None


def _inside(root, abspath_normcased):
    return abspath_normcased == root or abspath_normcased.startswith(root + os.sep)


def _path_allowed(p):
    if isinstance(p, int):
        return True  # an already-open descriptor, not a filesystem path
    ap = _decode_path(p)
    if ap is None:
        return False
    return _inside(ALLOWED_ROOT, ap)


def _guard_open(file, *args, **kwargs):
    if not _path_allowed(file):
        tripwire_read_attempts.append(repr(file))
        raise PermissionError(
            "input-closure violation: open() outside %s: %r" % (WORK_ROOT, file))
    return _real_open(file, *args, **kwargs)


def _guard_os_open(path, flags, mode=0o777, *, dir_fd=None):
    if not _path_allowed(path):
        tripwire_read_attempts.append(repr(path))
        raise PermissionError(
            "input-closure violation: os.open() outside %s: %r" % (WORK_ROOT, path))
    return _real_os_open(path, flags, mode, dir_fd=dir_fd)


class ClosureImportGuard:
    """sys.meta_path hook: refuse any import whose origin lies under the forbidden root."""

    def find_spec(self, fullname, path=None, target=None):
        for finder in list(sys.meta_path):
            if finder is self:
                continue
            find = getattr(finder, "find_spec", None)
            if find is None:
                continue
            spec = find(fullname, path, target)
            if spec is None:
                continue
            origin = getattr(spec, "origin", None)
            if origin and origin not in ("built-in", "frozen"):
                ap = _decode_path(origin)
                if ap is not None and _inside(FORBIDDEN_IMPORT_ROOT, ap):
                    tripwire_import_attempts.append("%s <- %s" % (fullname, origin))
                    raise ImportError(
                        "input-closure violation: import %r resolves under forbidden root: %s"
                        % (fullname, origin))
            return spec
        return None


def arm_closure():
    """Arm both guards. Called before the first data read."""
    builtins.open = _guard_open
    io.open = _guard_open
    os.open = _guard_os_open
    sys.meta_path.insert(0, ClosureImportGuard())
    kept = []
    for p in list(sys.path):
        ap = _decode_path(p)
        if ap is not None and _inside(FORBIDDEN_IMPORT_ROOT, ap):
            continue  # defense in depth; the meta_path hook is the recorded guard
        kept.append(p)
    sys.path[:] = kept


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def http_get(route):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=600)
    conn.request("GET", route, headers={"Accept": "*/*"})
    return conn, conn.getresponse()


def fetch_manifest():
    conn, resp = http_get("/api/manifest")
    try:
        if resp.status != 200:
            raise RuntimeError("manifest HTTP %s" % resp.status)
        raw = resp.read()
    finally:
        conn.close()
    doc = json.loads(raw.decode("utf-8"))
    if isinstance(doc, dict) and isinstance(doc.get("sources"), list):
        entries = doc["sources"]
    elif isinstance(doc, list):
        entries = doc
    else:
        raise RuntimeError("unrecognized manifest shape")
    by_id = {}
    for e in entries:
        if isinstance(e, dict) and "id" in e:
            by_id[str(e["id"])] = e
    return by_id


def stream_source(tag16):
    """Stream /api/source/<tag16>; return (sha256_hex, byte_count). Never buffers the document."""
    conn, resp = http_get("/api/source/%s" % tag16)
    try:
        if resp.status != 200:
            raise RuntimeError("source HTTP %s for tag16=%s" % (resp.status, tag16))
        digest = hashlib.sha256()
        count = 0
        while True:
            chunk = resp.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            count += len(chunk)
        return digest.hexdigest(), count
    finally:
        conn.close()


def build_receipt(source_id, tag16, green, folded, nbytes, wire_pin, impl_sha, failure):
    source_route = ("http://127.0.0.1:8821/api/source/%s" % tag16) if tag16 else \
        "http://127.0.0.1:8821/api/source/<tag16>"
    closure_held = (not tripwire_read_attempts) and (not tripwire_import_attempts)
    receipt = {
        "independent_non_author": bool(green),
        "provenance_mode": "claude_agent_clean_room",
        "external_session_id": SESSION_ID,
        "public_repository": PUBLIC_REPOSITORY,
        "inputs_permitted": [
            "http://127.0.0.1:8821/api/manifest",
            source_route,
        ],
        "tripwire_import_attempts": list(tripwire_import_attempts),
        "tripwire_read_attempts": list(tripwire_read_attempts),
        "input_closure_held": closure_held,
        "source": source_id,
        "folded_sha256": folded,
        "bytes_verified": nbytes,
        "wire_pin_sha256": wire_pin,
        "equivalence_level": "L_byte, whole document, recovered from the wire alone under enforced closure",
        "does_NOT_prove": [
            "publisher fidelity — link 1 is a separate anchor",
            "spec-sufficiency for reconstruction from typed surfaces — a spec-emit commission is the stronger form",
            "anything about other sources",
        ],
        "utc": utc_now(),
        "implementation_sha256": impl_sha,
    }
    if failure is not None:
        receipt["failure"] = failure
    return receipt


def write_receipt(receipt):
    path = os.path.join(WORK_ROOT, "commission_%s_receipt.json" % receipt["source"])
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(receipt, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return path


def main():
    print("[kaiser6] external_session_id=%s" % SESSION_ID, flush=True)
    arm_closure()
    print("[kaiser6] input closure armed (open/io.open/os.open guard + meta_path import guard)", flush=True)

    impl_path = os.path.abspath(__file__)
    digest = hashlib.sha256()
    with open(impl_path, "rb") as f:
        while True:
            block = f.read(1 << 20)
            if not block:
                break
            digest.update(block)
    impl_sha = digest.hexdigest()
    print("[kaiser6] implementation_sha256=%s" % impl_sha, flush=True)

    manifest_error = None
    try:
        by_id = fetch_manifest()
        print("[kaiser6] manifest: %d sources on the wire" % len(by_id), flush=True)
    except Exception as exc:
        by_id = {}
        manifest_error = "manifest fetch failed: %s" % exc
        print("[kaiser6] " + manifest_error, flush=True)

    outcomes = []  # (source_id, tag16, green, folded, nbytes, wire_pin, failure, seconds)
    for source_id in REQUIRED_IDS:
        started = time.time()
        entry = by_id.get(source_id)
        if entry is None:
            failure = manifest_error or ("source id %r not present in wire manifest" % source_id)
            outcomes.append((source_id, None, False, None, None, None, failure, 0.0))
            print("[kaiser6] %s: FAIL (%s)" % (source_id, failure), flush=True)
            continue
        try:
            wire_pin = str(entry["member_sha256"]).strip()
            want_bytes = int(entry["member_bytes"])
        except Exception as exc:
            failure = "manifest entry unusable: %s" % exc
            outcomes.append((source_id, None, False, None, None, None, failure, 0.0))
            print("[kaiser6] %s: FAIL (%s)" % (source_id, failure), flush=True)
            continue
        tag16 = wire_pin[:16]
        try:
            folded, nbytes = stream_source(tag16)
        except Exception as exc:
            failure = "stream failed: %s" % exc
            outcomes.append((source_id, tag16, False, None, None, wire_pin, failure, time.time() - started))
            print("[kaiser6] %s: FAIL (%s)" % (source_id, failure), flush=True)
            continue
        sha_ok = folded.lower() == wire_pin.lower()
        bytes_ok = nbytes == want_bytes
        problems = []
        if not sha_ok:
            problems.append("sha mismatch: streamed %s != wire pin %s" % (folded, wire_pin))
        if not bytes_ok:
            problems.append("byte-count mismatch: streamed %d != wire %d" % (nbytes, want_bytes))
        failure = "; ".join(problems) if problems else None
        green = failure is None
        outcomes.append((source_id, tag16, green, folded, nbytes, wire_pin, failure, time.time() - started))
        print("[kaiser6] %s: %s sha=%s bytes=%d %.1fs" % (
            source_id, "GREEN" if green else "FAIL", folded, nbytes, time.time() - started), flush=True)

    closure_clean = (not tripwire_read_attempts) and (not tripwire_import_attempts)

    results = []
    for (source_id, tag16, green, folded, nbytes, wire_pin, failure, seconds) in outcomes:
        final_green = green and closure_clean
        final_failure = failure
        if green and not closure_clean:
            final_failure = "tripwires fired during the run: reads=%d imports=%d" % (
                len(tripwire_read_attempts), len(tripwire_import_attempts))
        receipt = build_receipt(source_id, tag16, final_green, folded, nbytes, wire_pin, impl_sha, final_failure)
        path = write_receipt(receipt)
        results.append({
            "source": source_id,
            "tag16": tag16,
            "green": final_green,
            "folded_sha256": folded,
            "bytes_verified": nbytes,
            "wire_pin_sha256": wire_pin,
            "seconds": round(seconds, 1),
            "receipt": path,
            "failure": final_failure,
        })

    all_green = (len(results) == len(REQUIRED_IDS)
                 and all(r["green"] for r in results)
                 and closure_clean)
    summary = {
        "commission": "kaiser6 six-source wire recovery (clean room)",
        "external_session_id": SESSION_ID,
        "serve": "http://127.0.0.1:8821",
        "required_ids": REQUIRED_IDS,
        "results": results,
        "tripwire_import_attempts": list(tripwire_import_attempts),
        "tripwire_read_attempts": list(tripwire_read_attempts),
        "input_closure_held": closure_clean,
        "all_green": all_green,
        "implementation_sha256": impl_sha,
        "utc": utc_now(),
    }
    with open(os.path.join(WORK_ROOT, "commission_run_summary.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("[kaiser6] all_green=%s tripwires=%d/%d" % (
        all_green, len(tripwire_import_attempts), len(tripwire_read_attempts)), flush=True)
    return 0 if all_green else 2


if __name__ == "__main__":
    sys.exit(main())
