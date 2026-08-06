#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Clean-room commission: single-source wire recovery of "hosp-westoahu"
from http://127.0.0.1:8821, under enforced input closure.

Provenance: claude_agent_clean_room. Python stdlib only. Written from the
commission spec alone; no repository file was read to produce this client.

Data channel: HTTP only --
    GET /api/manifest            JSON pin: sources[] carry id, member_sha256, member_bytes
    GET /api/source/<tag16>      document byte stream; tag16 = member_sha256[:16]

Enforced input closure (armed BEFORE the first data read):
  * open() guard on builtins.open / io.open / os.open -- any path outside
    C:/Temp/gs_commission_westoahu/ is recorded in tripwire_read_attempts and RAISES.
  * import guard (sys.meta_path hook) -- any module whose origin lies under
    C:/Users/keith/Payer is recorded in tripwire_import_attempts and RAISES.

GREEN = streamed sha256 == wire member_sha256 for hosp-westoahu
        AND streamed byte count == wire member_bytes
        AND both tripwire lists empty (0/0).
"""

import sys
import os
import io
import json
import uuid
import hashlib
import builtins
import datetime
import importlib.machinery
import urllib.request

# ------------------------------------------------------------------ constants
BASE           = "http://127.0.0.1:8821"
SOURCE_ID      = "hosp-westoahu"
CHUNK          = 4 * 1024 * 1024          # 4 MB
WORK_DIR       = "C:/Temp/gs_commission_westoahu"
RECEIPT_PATH   = WORK_DIR + "/commission_hosp-westoahu_receipt.json"
ALLOWED_ROOT   = os.path.normcase(os.path.abspath(WORK_DIR))
FORBIDDEN_REPO = os.path.normcase(os.path.abspath("C:/Users/keith/Payer"))

SESSION_ID = str(uuid.uuid4())            # minted at start

tripwire_read_attempts = []
tripwire_import_attempts = []

# ------------------------------------------------------------- input closure
def _norm_path(p):
    if isinstance(p, int):                # fd pass-through, not a filesystem path
        return None
    try:
        p = os.fspath(p)
    except TypeError:
        return None
    if isinstance(p, bytes):
        try:
            p = os.fsdecode(p)
        except Exception:
            return "<undecodable>"
    return os.path.normcase(os.path.abspath(p))

def _allowed(p):
    n = _norm_path(p)
    if n is None:
        return True
    return n == ALLOWED_ROOT or n.startswith(ALLOWED_ROOT + os.sep)

_real_open    = builtins.open
_real_io_open = io.open
_real_os_open = os.open

def _guarded_open(file, *args, **kwargs):
    if not _allowed(file):
        tripwire_read_attempts.append("open:%r" % (file,))
        raise PermissionError("input-closure violation: open(%r)" % (file,))
    return _real_open(file, *args, **kwargs)

def _guarded_io_open(file, *args, **kwargs):
    if not _allowed(file):
        tripwire_read_attempts.append("io.open:%r" % (file,))
        raise PermissionError("input-closure violation: io.open(%r)" % (file,))
    return _real_io_open(file, *args, **kwargs)

def _guarded_os_open(path, flags, mode=0o777, *, dir_fd=None):
    if not _allowed(path):
        tripwire_read_attempts.append("os.open:%r" % (path,))
        raise PermissionError("input-closure violation: os.open(%r)" % (path,))
    return _real_os_open(path, flags, mode, dir_fd=dir_fd)

class _ClosureImportGuard:
    """sys.meta_path hook: refuse any module whose origin lies under the repo."""
    def find_spec(self, fullname, path=None, target=None):
        try:
            spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
        except Exception:
            return None
        origin = getattr(spec, "origin", None) if spec is not None else None
        if isinstance(origin, str) and origin not in ("built-in", "frozen"):
            n = os.path.normcase(os.path.abspath(origin))
            if n == FORBIDDEN_REPO or n.startswith(FORBIDDEN_REPO + os.sep):
                tripwire_import_attempts.append("%s -> %s" % (fullname, origin))
                raise ImportError(
                    "input-closure violation: import %s from %s" % (fullname, origin))
        return None                       # defer to the normal import machinery

def arm_guards():
    builtins.open = _guarded_open
    io.open       = _guarded_io_open
    os.open       = _guarded_os_open
    sys.meta_path.insert(0, _ClosureImportGuard())

# ------------------------------------------------------------------- wire IO
def http_get(url, timeout=300):
    req = urllib.request.Request(
        url, headers={"User-Agent": "gs-commission-westoahu-clean-room"})
    return urllib.request.urlopen(req, timeout=timeout)

def fetch_manifest():
    with http_get(BASE + "/api/manifest", timeout=60) as resp:
        raw = resp.read()                 # small pin document only
    return json.loads(raw.decode("utf-8"))

def pin_from_wire(manifest):
    hits = [s for s in manifest.get("sources", []) if s.get("id") == SOURCE_ID]
    if len(hits) != 1:
        raise RuntimeError("manifest pins %d entries for id %r (need exactly 1)"
                           % (len(hits), SOURCE_ID))
    src = hits[0]
    sha = str(src["member_sha256"]).strip().lower()
    nbytes = int(src["member_bytes"])
    if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        raise RuntimeError("wire pin is not a sha256 hex digest: %r" % (sha,))
    if nbytes <= 0:
        raise RuntimeError("wire pin byte count not positive: %r" % (nbytes,))
    return sha, nbytes

def stream_and_fold(tag16):
    h = hashlib.sha256()
    count = 0
    with http_get(BASE + "/api/source/" + tag16, timeout=300) as resp:
        while True:
            chunk = resp.read(CHUNK)      # 4 MB at a time
            if not chunk:
                break
            h.update(chunk)               # fold on the fly -- never buffer the document
            count += len(chunk)
    return h.hexdigest(), count

# ------------------------------------------------------------------- receipt
def write_receipt(green, folded, bytes_verified, pin_sha, failure=None):
    with open(__file__, "rb") as f:       # own file, inside the allowed root
        impl_sha = hashlib.sha256(f.read()).hexdigest()
    receipt = {
        "independent_non_author": bool(green),
        "provenance_mode": "claude_agent_clean_room",
        "external_session_id": SESSION_ID,
        "public_repository": "https://github.com/keithkallison-ai/mera-az",
        "public_commit": "pending",
        "inputs_permitted": [
            "http://127.0.0.1:8821/api/manifest",
            "http://127.0.0.1:8821/api/source/<tag16>",
        ],
        "tripwire_import_attempts": list(tripwire_import_attempts),
        "tripwire_read_attempts": list(tripwire_read_attempts),
        "input_closure_held": (not tripwire_import_attempts)
                              and (not tripwire_read_attempts),
        "source": SOURCE_ID,
        "folded_sha256": folded,
        "bytes_verified": bytes_verified,
        "wire_pin_sha256": pin_sha,
        "equivalence_level": "L_byte, whole document, recovered from the wire "
                             "alone under enforced closure",
        "does_NOT_prove": [
            "publisher fidelity \u2014 link 1 is a separate anchor",
            "spec-sufficiency for reconstruction from typed surfaces \u2014 "
            "a spec-emit commission is the stronger form",
            "anything about other sources",
        ],
        "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "implementation_sha256": impl_sha,
    }
    if not green:
        receipt["failure"] = failure or "unspecified"
    with open(RECEIPT_PATH, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return receipt

# ---------------------------------------------------------------------- main
def main():
    arm_guards()                          # armed BEFORE the first data read
    folded = None
    count = None
    pin = None
    nbytes = None
    failure = None
    try:
        manifest = fetch_manifest()
        pin, nbytes = pin_from_wire(manifest)
        folded, count = stream_and_fold(pin[:16])
    except Exception as e:
        failure = "%s: %s" % (type(e).__name__, e)
    trips_clean = (not tripwire_import_attempts) and (not tripwire_read_attempts)
    green = (failure is None and folded == pin and count == nbytes and trips_clean)
    if not green and failure is None:
        failure = ("verification mismatch: folded=%s wire_pin=%s bytes=%s "
                   "expected_bytes=%s import_trips=%d read_trips=%d"
                   % (folded, pin, count, nbytes,
                      len(tripwire_import_attempts), len(tripwire_read_attempts)))
    write_receipt(green, folded, count if count is not None else 0,
                  pin or "", failure)
    print(json.dumps({
        "verdict": "GREEN" if green else "RED",
        "session": SESSION_ID,
        "folded_sha256": folded,
        "wire_pin_sha256": pin,
        "bytes_verified": count,
        "wire_pin_bytes": nbytes,
        "tripwire_import_attempts": len(tripwire_import_attempts),
        "tripwire_read_attempts": len(tripwire_read_attempts),
        "failure": failure,
    }))
    return 0 if green else 2

if __name__ == "__main__":
    sys.exit(main())
