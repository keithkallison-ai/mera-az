#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Clean-room single-source wire recovery client — commission artifact.

Deliverable: holding NOTHING local, recover the source document with id
"cigna-oap-2026-08" from the wire alone:

    GET http://127.0.0.1:8821/api/manifest
    GET http://127.0.0.1:8821/api/source/<tag16>   (tag16 = member_sha256[:16])

The document (~34.5 GB) is streamed in 4 MB chunks, sha256 folded on the fly,
bytes counted; it is never buffered whole and never written to disk. A broken
stream is a failure to report, not to paper over (no mid-stream retry).

GREEN = streamed sha256 == wire member_sha256 AND byte count == member_bytes,
tripwires 0/0.

ENFORCED INPUT CLOSURE (armed before the first data read):
  * open() guard  — builtins.open / io.open / os.open RAISE on any path
    outside C:/Temp/gs_commission_cigna/; attempts recorded in
    tripwire_read_attempts.
  * import guard  — a sys.meta_path hook RAISES on any module whose origin
    lies under C:\\Users\\keith\\Payer; attempts recorded in
    tripwire_import_attempts.
HTTP is the only data channel. Python stdlib only.

Provenance: written clean-room from the commission spec by a Claude agent
with no project context (provenance_mode "claude_agent_clean_room").
"""

import builtins
import hashlib
import io
import json
import os
import socket  # noqa: F401  pre-imported so no lazy import occurs post-arm
import sys
import time
import urllib.error  # noqa: F401
import urllib.request
import uuid
from datetime import datetime, timezone
from importlib.machinery import PathFinder

# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------
ALLOWED_DIR = "C:/Temp/gs_commission_cigna"
FORBIDDEN_IMPORT_ROOT = "C:/Users/keith/Payer"
BASE = "http://127.0.0.1:8821"
SOURCE_ID = "cigna-oap-2026-08"
CHUNK_BYTES = 4 * 1024 * 1024
SOCKET_TIMEOUT_S = 600.0
RECEIPT_PATH = ALLOWED_DIR + "/commission_" + SOURCE_ID + "_receipt.json"
PUBLIC_REPOSITORY = "https://github.com/keithkallison-ai/mera-az"

_ALLOWED_ROOT = os.path.normcase(os.path.abspath(ALLOWED_DIR))
_ALLOWED_PREFIX = _ALLOWED_ROOT + os.sep
_FORBIDDEN_ROOT = os.path.normcase(os.path.abspath(FORBIDDEN_IMPORT_ROOT))
_FORBIDDEN_PREFIX = _FORBIDDEN_ROOT + os.sep

tripwire_read_attempts = []
tripwire_import_attempts = []

_real_builtins_open = builtins.open
_real_os_open = os.open


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _path_allowed(p):
    """True iff p resolves inside the allowed working directory."""
    try:
        if isinstance(p, int):
            return False  # fd-relative open: closure cannot be proven
        n = os.path.normcase(os.path.abspath(os.fspath(p)))
        return n == _ALLOWED_ROOT or n.startswith(_ALLOWED_PREFIX)
    except Exception:
        return False


def _record_read_attempt(api, target):
    tripwire_read_attempts.append(
        {"api": api, "path": repr(target), "utc": _utc_now()}
    )


def _guarded_builtins_open(file, *args, **kwargs):
    if not _path_allowed(file):
        _record_read_attempt("builtins.open/io.open", file)
        raise PermissionError(
            "input-closure violation: open() outside %s: %r"
            % (ALLOWED_DIR, file)
        )
    return _real_builtins_open(file, *args, **kwargs)


def _guarded_os_open(path, flags, *args, **kwargs):
    if kwargs.get("dir_fd") is not None or not _path_allowed(path):
        _record_read_attempt("os.open", path)
        raise PermissionError(
            "input-closure violation: os.open() outside %s: %r"
            % (ALLOWED_DIR, path)
        )
    return _real_os_open(path, flags, *args, **kwargs)


class _ImportClosureGuard:
    """sys.meta_path hook: RAISE on any module whose origin lies under the
    forbidden root; defer everything else to the normal machinery."""

    def find_spec(self, fullname, path=None, target=None):
        try:
            spec = PathFinder.find_spec(fullname, path, target)
        except Exception:
            return None
        origin = getattr(spec, "origin", None) if spec else None
        if isinstance(origin, str) and origin not in ("built-in", "frozen"):
            try:
                n = os.path.normcase(os.path.abspath(origin))
            except Exception:
                return None
            if n == _FORBIDDEN_ROOT or n.startswith(_FORBIDDEN_PREFIX):
                tripwire_import_attempts.append(
                    {"module": fullname, "origin": origin, "utc": _utc_now()}
                )
                raise ImportError(
                    "input-closure violation: import %r resolves under %s"
                    % (fullname, FORBIDDEN_IMPORT_ROOT)
                )
        return None


def arm_guards():
    builtins.open = _guarded_builtins_open
    io.open = _guarded_builtins_open
    os.open = _guarded_os_open
    sys.meta_path.insert(0, _ImportClosureGuard())


def _http_get(url):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "gs-clean-room-commission/1.0"},
        method="GET",
    )
    return urllib.request.urlopen(req, timeout=SOCKET_TIMEOUT_S)


def main():
    t_start = time.monotonic()
    session_id = str(uuid.uuid4())

    arm_guards()  # armed before the first data read

    failure = None
    wire_pin = None
    member_bytes = None
    folded = None
    n_bytes = 0
    stream_s = None

    try:
        # ---- manifest (data read #1) ----
        with _http_get(BASE + "/api/manifest") as r:
            manifest = json.loads(r.read().decode("utf-8"))
        sources = (
            manifest.get("sources") if isinstance(manifest, dict) else manifest
        )
        if not isinstance(sources, list):
            raise RuntimeError("wire manifest carries no sources[] list")
        entry = None
        for s in sources:
            if isinstance(s, dict) and s.get("id") == SOURCE_ID:
                entry = s
                break
        if entry is None:
            raise RuntimeError(
                "source id %r not present in wire manifest" % SOURCE_ID
            )
        wire_pin = str(entry["member_sha256"]).strip().lower()
        member_bytes = int(entry["member_bytes"])
        if len(wire_pin) != 64 or any(
            c not in "0123456789abcdef" for c in wire_pin
        ):
            raise RuntimeError(
                "wire member_sha256 is not 64 lowercase hex chars: %r"
                % wire_pin
            )
        tag16 = wire_pin[:16]

        # ---- stream (data read #2): sha256 on the fly, never buffered ----
        h = hashlib.sha256()
        t0 = time.monotonic()
        chunk_i = 0
        with _http_get(BASE + "/api/source/" + tag16) as r:
            while True:
                chunk = r.read(CHUNK_BYTES)
                if not chunk:
                    break
                h.update(chunk)
                n_bytes += len(chunk)
                chunk_i += 1
                if chunk_i % 1024 == 0:  # every ~4 GiB, machine-facing
                    el = time.monotonic() - t0
                    sys.stderr.write(
                        "progress bytes=%d gib=%.2f elapsed_s=%.1f mbps=%.1f\n"
                        % (
                            n_bytes,
                            n_bytes / 2**30,
                            el,
                            (n_bytes / 2**20) / el if el > 0 else 0.0,
                        )
                    )
                    sys.stderr.flush()
        stream_s = time.monotonic() - t0
        folded = h.hexdigest()
    except BaseException as e:  # a broken stream is a failure to REPORT
        failure = "%s: %s" % (type(e).__name__, e)

    trips_ok = (
        len(tripwire_read_attempts) == 0 and len(tripwire_import_attempts) == 0
    )
    green = (
        failure is None
        and folded is not None
        and wire_pin is not None
        and folded == wire_pin
        and member_bytes is not None
        and n_bytes == member_bytes
        and trips_ok
    )
    if failure is None and not green:
        if folded != wire_pin:
            failure = "sha mismatch: folded %s != wire pin %s" % (
                folded,
                wire_pin,
            )
        elif n_bytes != member_bytes:
            failure = "byte-count mismatch: streamed %d != member_bytes %d" % (
                n_bytes,
                member_bytes,
            )
        else:
            failure = "input-closure tripwire(s) recorded"

    # ---- self-hash of this implementation file (inside allowed dir) ----
    implementation_sha256 = None
    try:
        hh = hashlib.sha256()
        with open(os.path.abspath(__file__), "rb") as f:
            for blk in iter(lambda: f.read(1 << 20), b""):
                hh.update(blk)
        implementation_sha256 = hh.hexdigest()
    except Exception as e:
        if failure is None:
            failure = "self-hash failed: %s: %s" % (type(e).__name__, e)
            green = False

    receipt = {
        "independent_non_author": bool(green),
        "provenance_mode": "claude_agent_clean_room",
        "external_session_id": session_id,
        "public_repository": PUBLIC_REPOSITORY,
        "public_commit": "PENDING_PUBLICATION" if green else "NOT_PUBLISHED",
        "inputs_permitted": [
            "http://127.0.0.1:8821/api/manifest",
            "http://127.0.0.1:8821/api/source/<tag16>",
        ],
        "tripwire_import_attempts": tripwire_import_attempts,
        "tripwire_read_attempts": tripwire_read_attempts,
        "input_closure_held": trips_ok,
        "source": SOURCE_ID,
        "folded_sha256": folded,
        "bytes_verified": n_bytes,
        "wire_pin_sha256": wire_pin,
        "equivalence_level": (
            "L_byte, whole document, recovered from the wire alone "
            "under enforced closure"
        ),
        "does_NOT_prove": [
            "publisher fidelity — link 1 is a separate anchor",
            "spec-sufficiency for reconstruction from typed surfaces — "
            "a spec-emit commission is the stronger form",
            "anything about other sources",
        ],
        "utc": _utc_now(),
        "implementation_sha256": implementation_sha256,
    }
    if not green:
        receipt["failure"] = failure or "unknown"

    with open(RECEIPT_PATH, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2, ensure_ascii=False)
        f.write("\n")

    summary = {
        "verdict": "GREEN" if green else "failure",
        "session": session_id,
        "source": SOURCE_ID,
        "wire_pin_sha256": wire_pin,
        "folded_sha256": folded,
        "member_bytes": member_bytes,
        "bytes_verified": n_bytes,
        "elapsed_stream_s": round(stream_s, 3) if stream_s is not None else None,
        "elapsed_total_s": round(time.monotonic() - t_start, 3),
        "tripwire_read_attempts": len(tripwire_read_attempts),
        "tripwire_import_attempts": len(tripwire_import_attempts),
        "receipt_path": RECEIPT_PATH,
        "implementation_sha256": implementation_sha256,
    }
    if failure is not None:
        summary["failure"] = failure
    sys.stdout.write(json.dumps(summary, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    sys.exit(0 if green else 1)


if __name__ == "__main__":
    main()
