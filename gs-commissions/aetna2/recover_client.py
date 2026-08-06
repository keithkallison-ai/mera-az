"""aetna-2 clean-room commission - two-source wire recovery under enforced input closure.

Clean-room implementation written from the commission spec alone. Python stdlib only.
The ONLY data channel is the serve at http://127.0.0.1:8821, exactly two routes:

    GET /api/manifest          JSON; sources[] carry id, member_sha256, member_bytes
    GET /api/source/<tag16>    streams document bytes; tag16 = member_sha256[:16]

Input closure is ENFORCED IN CODE, armed before the first data read:

  * builtins.open / io.open / os.open RAISE on any path outside
    C:/Temp/gs_commission_aetna2/ ; attempts recorded in tripwire_read_attempts.
  * a sys.meta_path hook RAISES on any import whose resolved origin lies under
    C:/Users/keith/Payer ; attempts recorded in tripwire_import_attempts.

GREEN per source = streamed sha256 == wire member_sha256 AND byte count ==
wire member_bytes AND both tripwire lists empty (0/0).

Modes:
    python recover_client.py                  run recovery, write one receipt per source
    python recover_client.py --stamp <sha>    set public_commit=<sha> in local receipts
"""

import builtins
import datetime
import hashlib
import http.client
import importlib.machinery
import io
import json
import linecache  # pre-imported so exception paths never trigger a post-arm import
import os
import socket    # pre-imported (http.client dependency), explicit for clarity
import sys
import time
import traceback  # pre-imported for the same reason as linecache
import uuid
import warnings

WORKDIR = "C:/Temp/gs_commission_aetna2"
PAYER_ROOT = "C:\\Users\\keith\\Payer"
HOST = "127.0.0.1"
PORT = 8821
SOURCE_IDS = ["aetna-utah-pl5rp", "aetna-iowa-pl2am"]
CHUNK = 4 * 1024 * 1024  # 4 MB
REPO_URL = "https://github.com/keithkallison-ai/mera-az"

_WORK_BASE = os.path.normcase(os.path.abspath(WORKDIR))
_PAYER_BASE = os.path.normcase(os.path.abspath(PAYER_ROOT))

tripwire_read_attempts = []
tripwire_import_attempts = []
_armed = False

_real_open = builtins.open
_real_os_open = os.open


def _path_allowed(target):
    """True only for already-open fds or paths inside the working directory."""
    if isinstance(target, int):
        return True
    try:
        p = os.fspath(target)
        if isinstance(p, bytes):
            p = os.fsdecode(p)
        n = os.path.normcase(os.path.abspath(p))
    except Exception:
        return False
    return n == _WORK_BASE or n.startswith(_WORK_BASE + os.sep)


def _guard_open(file, *args, **kwargs):
    if _armed and not _path_allowed(file):
        tripwire_read_attempts.append({"api": "open", "path": repr(file)})
        raise PermissionError("input-closure violation: open(%r)" % (file,))
    return _real_open(file, *args, **kwargs)


def _guard_os_open(path, *args, **kwargs):
    if _armed and not _path_allowed(path):
        tripwire_read_attempts.append({"api": "os.open", "path": repr(path)})
        raise PermissionError("input-closure violation: os.open(%r)" % (path,))
    return _real_os_open(path, *args, **kwargs)


class _ImportClosureGuard:
    """sys.meta_path hook: refuses any import whose origin lies under PAYER_ROOT."""

    def find_spec(self, name, path=None, target=None):
        if not _armed:
            return None
        try:
            spec = importlib.machinery.PathFinder.find_spec(name, path, target)
        except Exception:
            return None
        origin = getattr(spec, "origin", None) if spec is not None else None
        if isinstance(origin, str) and origin not in ("built-in", "frozen"):
            try:
                n = os.path.normcase(os.path.abspath(origin))
            except Exception:
                return None
            if n == _PAYER_BASE or n.startswith(_PAYER_BASE + os.sep):
                tripwire_import_attempts.append({"module": name, "origin": origin})
                raise ImportError(
                    "input-closure violation: import %s from %s" % (name, origin)
                )
        return None  # not ours to load; normal machinery proceeds


def _prewarm():
    """Touch every lazily-loaded codec/path needed later, BEFORE arming the guards."""
    "127.0.0.1".encode("idna")
    "x".encode("utf-8").decode("utf-8")
    "x".encode("ascii")
    "x".encode("latin-1")
    json.loads(json.dumps({"k": 1}))
    hashlib.sha256(b"x").hexdigest()
    datetime.datetime.now(datetime.timezone.utc).isoformat()
    warnings.simplefilter("ignore")
    # terse excepthook: never let a traceback printer open stdlib source files
    sys.excepthook = lambda t, v, tb: print(
        "FATAL %s: %s" % (t.__name__, v), file=sys.stderr, flush=True
    )


def _arm():
    global _armed
    builtins.open = _guard_open
    io.open = _guard_open
    os.open = _guard_os_open
    sys.meta_path.insert(0, _ImportClosureGuard())
    _armed = True


def _http_get(path):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=300)
    conn.request("GET", path, headers={"Accept-Encoding": "identity"})
    resp = conn.getresponse()
    return conn, resp


def _fetch_manifest():
    conn, resp = _http_get("/api/manifest")
    try:
        if resp.status != 200:
            raise RuntimeError("manifest HTTP %d" % resp.status)
        return json.loads(resp.read().decode("utf-8"))
    finally:
        conn.close()


def _stream_source(tag16):
    """Stream /api/source/<tag16> in 4 MB chunks; sha256 on the fly; never buffer."""
    digest = hashlib.sha256()
    count = 0
    next_mark = 1 << 30
    conn, resp = _http_get("/api/source/" + tag16)
    try:
        if resp.status != 200:
            raise RuntimeError("source HTTP %d for tag16=%s" % (resp.status, tag16))
        while True:
            chunk = resp.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            count += len(chunk)
            if count >= next_mark:
                print("PROGRESS tag16=%s bytes=%d" % (tag16, count), flush=True)
                next_mark += 1 << 30
    finally:
        conn.close()
    return digest.hexdigest(), count


def _receipt(sid, ok, folded, count, pin, tag16, session_id, impl_sha, failure):
    receipt = {
        "independent_non_author": bool(ok),
        "provenance_mode": "claude_agent_clean_room",
        "external_session_id": session_id,
        "public_repository": REPO_URL,
        "public_commit": "PENDING_PUBLICATION",
        "inputs_permitted": [
            "http://%s:%d/api/manifest" % (HOST, PORT),
            "http://%s:%d/api/source/%s" % (HOST, PORT, tag16),
        ],
        "tripwire_import_attempts": list(tripwire_import_attempts),
        "tripwire_read_attempts": list(tripwire_read_attempts),
        "input_closure_held": bool(
            _armed and not tripwire_import_attempts and not tripwire_read_attempts
        ),
        "source": sid,
        "folded_sha256": folded,
        "bytes_verified": count,
        "wire_pin_sha256": pin,
        "equivalence_level": "L_byte, whole document, recovered from the wire alone under enforced closure",
        "does_NOT_prove": [
            "publisher fidelity — link 1 is a separate anchor",
            "spec-sufficiency for reconstruction from typed surfaces — a spec-emit commission is the stronger form",
            "anything about other sources",
        ],
        "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "implementation_sha256": impl_sha,
    }
    if failure is not None:
        receipt["independent_non_author"] = False
        receipt["failure"] = failure
    return receipt


def _write_receipt(sid, receipt):
    rpath = os.path.join(WORKDIR, "commission_%s_receipt.json" % sid)
    with open(rpath, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return rpath


def _run():
    session_id = str(uuid.uuid4())
    print("SESSION %s" % session_id, flush=True)
    impl_path = os.path.abspath(__file__)
    _prewarm()
    _arm()
    print("ARMED open/io.open/os.open guard + meta_path import guard; workdir=%s"
          % _WORK_BASE, flush=True)
    with open(impl_path, "rb") as f:  # inside workdir: allowed by the armed guard
        impl_sha = hashlib.sha256(f.read()).hexdigest()
    print("IMPLEMENTATION sha256=%s" % impl_sha, flush=True)

    manifest_err = None
    by_id = {}
    try:
        manifest = _fetch_manifest()
        sources = manifest.get("sources", [])
        by_id = {str(s.get("id")): s for s in sources if isinstance(s, dict)}
        print("MANIFEST ids=%s" % ",".join(sorted(by_id)), flush=True)
    except Exception as exc:
        manifest_err = "manifest fetch failed: %s: %s" % (type(exc).__name__, exc)
        print(manifest_err, file=sys.stderr, flush=True)

    all_green = True
    for sid in SOURCE_IDS:
        t0 = time.monotonic()
        ok = False
        folded = ""
        count = 0
        pin = ""
        tag16 = "<tag16>"
        failure = None
        entry = by_id.get(sid)
        if manifest_err is not None:
            failure = manifest_err
        elif entry is None:
            failure = "source id %r not present in wire manifest" % sid
        else:
            try:
                pin = str(entry["member_sha256"]).strip()
                wire_bytes = int(entry["member_bytes"])
                if len(pin) != 64 or any(
                    c not in "0123456789abcdefABCDEF" for c in pin
                ):
                    raise ValueError("malformed member_sha256 on wire: %r" % pin)
                tag16 = pin[:16]
                folded, count = _stream_source(tag16)
                sha_ok = folded.lower() == pin.lower()
                bytes_ok = count == wire_bytes
                trips_ok = not tripwire_read_attempts and not tripwire_import_attempts
                ok = sha_ok and bytes_ok and trips_ok
                if not ok:
                    failure = (
                        "verification failed: sha_ok=%s bytes_ok=%s "
                        "(streamed=%d wire=%d) trips=%d/%d"
                        % (sha_ok, bytes_ok, count, wire_bytes,
                           len(tripwire_import_attempts),
                           len(tripwire_read_attempts))
                    )
            except Exception as exc:
                failure = "%s: %s" % (type(exc).__name__, exc)
        receipt = _receipt(sid, ok, folded, count, pin, tag16, session_id,
                           impl_sha, failure)
        rpath = _write_receipt(sid, receipt)
        dt = time.monotonic() - t0
        print(
            "VERDICT source=%s green=%s folded_sha256=%s bytes=%d wire_pin=%s "
            "trips=%d/%d secs=%.1f receipt=%s%s"
            % (sid, ok, folded or "-", count, pin or "-",
               len(tripwire_import_attempts), len(tripwire_read_attempts),
               dt, rpath, (" failure=" + failure) if failure else ""),
            flush=True,
        )
        if not ok:
            all_green = False
    return 0 if all_green else 1


def _stamp(sha):
    _prewarm()
    _arm()
    for sid in SOURCE_IDS:
        rpath = os.path.join(WORKDIR, "commission_%s_receipt.json" % sid)
        with open(rpath, "r", encoding="utf-8") as f:
            receipt = json.load(f)
        receipt["public_commit"] = sha
        with open(rpath, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print("STAMPED %s public_commit=%s" % (sid, sha), flush=True)
    return 0


def main(argv):
    if len(argv) >= 3 and argv[1] == "--stamp":
        return _stamp(argv[2])
    return _run()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
