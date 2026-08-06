#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""FLEXNET WIRE RECOVERY — clean-room, non-authorship commission.

A client holding NOTHING local that recovers the source document with id
"flexnet" from the wire alone:

    1. GET http://127.0.0.1:8821/api/manifest
       -> the pin (member_sha256, member_bytes) is taken FROM THE WIRE.
    2. GET http://127.0.0.1:8821/api/source/<tag16>   (tag16 = pin[:16])
       -> streamed in 4 MiB chunks, sha256 folded on the fly, bytes counted.
       The document is never buffered.

GREEN  =  streamed sha256 == manifest member_sha256 for "flexnet"
      AND streamed byte count == its member_bytes
      AND tripwire counts 0/0.

ENFORCED INPUT CLOSURE — armed in code before the first data read:
  * open guard   : builtins.open / io.open / os.open RAISE on any path outside
                   C:/Temp/gs_commission_flexnet/ ; attempts are recorded in
                   tripwire_read_attempts.
  * import guard : a sys.meta_path hook RAISES on any module whose origin lies
                   under C:/Users/keith/Payer ; attempts are recorded in
                   tripwire_import_attempts.
HTTP is the only data channel. Python stdlib only.

    --selftest : prove both guards can refuse and that attempts are recorded
                 (run in a separate process; writes no receipt, so the real
                 run's tripwire lists stay clean).
"""

import builtins
import io
import os
import sys
from importlib.machinery import PathFinder

WORK_DIR = "C:/Temp/gs_commission_flexnet"
PAYER_ROOT = "C:/Users/keith/Payer"

ALLOWED_NORM = os.path.normcase(os.path.abspath(WORK_DIR))
FORBIDDEN_NORM = os.path.normcase(os.path.abspath(PAYER_ROOT))

tripwire_read_attempts = []
tripwire_import_attempts = []

_real_open = builtins.open
_real_os_open = os.open


def _as_path_text(p):
    """Best-effort textual path; None for fd's / non-path objects."""
    if isinstance(p, int):
        return None
    try:
        s = os.fspath(p)
    except TypeError:
        return None
    if isinstance(s, bytes):
        try:
            s = os.fsdecode(s)
        except Exception:
            return "<undecodable-bytes-path>"
    return s


def _inside_workdir(p):
    s = _as_path_text(p)
    if s is None:
        return True  # bare fd: it was judged when created via the os.open guard
    try:
        n = os.path.normcase(os.path.abspath(s))
    except Exception:
        return False
    return n == ALLOWED_NORM or n.startswith(ALLOWED_NORM + os.sep)


def _guard_open(file, *args, **kwargs):
    if not _inside_workdir(file):
        tripwire_read_attempts.append("open:%r" % (file,))
        raise PermissionError(
            "input-closure violation: open(%r) is outside %s" % (file, WORK_DIR))
    return _real_open(file, *args, **kwargs)


def _guard_os_open(path, flags, *args, **kwargs):
    if not _inside_workdir(path):
        tripwire_read_attempts.append("os.open:%r" % (path,))
        raise PermissionError(
            "input-closure violation: os.open(%r) is outside %s" % (path, WORK_DIR))
    return _real_os_open(path, flags, *args, **kwargs)


def _origin_forbidden(s):
    try:
        n = os.path.normcase(os.path.abspath(s))
    except Exception:
        return False
    return n == FORBIDDEN_NORM or n.startswith(FORBIDDEN_NORM + os.sep)


class PayerImportGuard:
    """sys.meta_path hook: RAISES on any module resolving under the Payer repo.

    It never resolves a module itself (returns None on clean specs), so the
    normal import machinery proceeds untouched for everything legitimate.
    """

    def check_spec(self, fullname, spec):
        candidates = []
        origin = getattr(spec, "origin", None)
        if isinstance(origin, str):
            candidates.append(origin)
        locs = getattr(spec, "submodule_search_locations", None)
        if locs:
            for loc in list(locs):
                if isinstance(loc, str):
                    candidates.append(loc)
        for c in candidates:
            if _origin_forbidden(c):
                tripwire_import_attempts.append("%s -> %s" % (fullname, c))
                raise ImportError(
                    "input-closure violation: import %s resolves under %s"
                    % (fullname, PAYER_ROOT))

    def find_spec(self, fullname, path=None, target=None):
        try:
            spec = PathFinder.find_spec(fullname, path, target)
        except Exception:
            return None
        if spec is not None:
            self.check_spec(fullname, spec)  # raises on a Payer origin
        return None


_GUARD = PayerImportGuard()


def arm_closure():
    # scrub ambient resolution hazards first ('' / cwd entries, any Payer entry)
    cleaned = []
    for entry in sys.path:
        if entry == "":
            continue
        if _origin_forbidden(entry):
            continue
        cleaned.append(entry)
    sys.path[:] = cleaned
    builtins.open = _guard_open
    io.open = _guard_open
    os.open = _guard_os_open
    sys.meta_path.insert(0, _GUARD)


arm_closure()

# --- everything imported below passes through the armed closure --------------
import hashlib                            # noqa: E402
import http.client                        # noqa: E402
import json                               # noqa: E402
import time                               # noqa: E402
import uuid                               # noqa: E402
from datetime import datetime, timezone   # noqa: E402

HOST = "127.0.0.1"
PORT = 8821
CHUNK = 4 * 1024 * 1024                   # 4 MiB
SOURCE_ID = "flexnet"
RECEIPT_PATH = WORK_DIR + "/commission_flexnet_receipt.json"


def _http_get(path_q, timeout):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    conn.request("GET", path_q, headers={"Accept-Encoding": "identity"})
    resp = conn.getresponse()
    if resp.status != 200:
        head = resp.read(512)
        conn.close()
        raise RuntimeError("GET %s -> HTTP %s %s (%r)"
                           % (path_q, resp.status, resp.reason, head[:200]))
    return conn, resp


def fetch_manifest():
    last = None
    for _ in range(3):
        try:
            conn, resp = _http_get("/api/manifest", timeout=60)
            raw = resp.read()
            conn.close()
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:
            last = exc
            time.sleep(2)
    raise RuntimeError("manifest unreachable after 3 attempts: %r" % (last,))


def pick_source(manifest, source_id):
    sources = manifest.get("sources", manifest) if isinstance(manifest, dict) else manifest
    entries = []
    if isinstance(sources, list):
        entries = [e for e in sources if isinstance(e, dict)]
    elif isinstance(sources, dict):
        for k, v in sources.items():
            if isinstance(v, dict):
                e = dict(v)
                e.setdefault("id", k)
                entries.append(e)
    for e in entries:
        if e.get("id") == source_id:
            return e
    raise RuntimeError("source id %r not found in manifest sources[]" % source_id)


def stream_and_fold(tag16):
    """Stream /api/source/<tag16>; sha256 on the fly; never buffer the document."""
    conn, resp = _http_get("/api/source/" + tag16, timeout=900)
    folder = hashlib.sha256()
    count = 0
    while True:
        chunk = resp.read(CHUNK)
        if not chunk:
            break
        folder.update(chunk)
        count += len(chunk)
    conn.close()
    return folder.hexdigest(), count


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def selftest():
    """Prove the closure can refuse. Separate process; writes NO receipt."""
    failures = []
    try:
        open("C:/Windows/win.ini", "rb")
        failures.append("open guard did NOT raise on an outside path")
    except PermissionError:
        pass
    try:
        os.open("C:/Windows/win.ini", os.O_RDONLY)
        failures.append("os.open guard did NOT raise on an outside path")
    except PermissionError:
        pass

    class _FakePayerSpec:
        origin = PAYER_ROOT + "/Workshop/fake_module.py"
        submodule_search_locations = None

    try:
        _GUARD.check_spec("fake_module", _FakePayerSpec())
        failures.append("import guard did NOT raise on a Payer-origin spec")
    except ImportError:
        pass

    probe = WORK_DIR + "/_selftest_probe.txt"
    try:
        with open(probe, "w", encoding="utf-8") as f:
            f.write("probe")
        with open(probe, "r", encoding="utf-8") as f:
            if f.read() != "probe":
                failures.append("allowed in-workdir round-trip mismatched")
    except Exception as exc:
        failures.append("allowed open inside workdir failed: %r" % (exc,))
    finally:
        try:
            os.remove(probe)
        except OSError:
            pass

    if len(tripwire_read_attempts) != 2:
        failures.append("read tripwire recorded %d attempts, expected 2"
                        % len(tripwire_read_attempts))
    if len(tripwire_import_attempts) != 1:
        failures.append("import tripwire recorded %d attempts, expected 1"
                        % len(tripwire_import_attempts))

    green = not failures
    print(json.dumps({
        "selftest_green": green,
        "read_trips_recorded": len(tripwire_read_attempts),
        "import_trips_recorded": len(tripwire_import_attempts),
        "failures": failures,
    }))
    return 0 if green else 1


def main():
    session_id = str(uuid.uuid4())

    wire_pin = ""
    member_bytes = None
    tag16 = ""
    folded = ""
    count = 0
    failure_notes = []

    try:
        manifest = fetch_manifest()                    # first data read
        entry = pick_source(manifest, SOURCE_ID)
        wire_pin = str(entry.get("member_sha256", "")).strip().lower()
        if len(wire_pin) != 64 or any(c not in "0123456789abcdef" for c in wire_pin):
            raise RuntimeError("wire pin member_sha256 malformed: %r"
                               % entry.get("member_sha256"))
        mb = entry.get("member_bytes")
        if isinstance(mb, str) and mb.isdigit():
            mb = int(mb)
        if not isinstance(mb, int) or isinstance(mb, bool) or mb < 0:
            raise RuntimeError("member_bytes malformed: %r" % (mb,))
        member_bytes = mb
        tag16 = wire_pin[:16]
        folded, count = stream_and_fold(tag16)
    except Exception as exc:
        failure_notes.append("EXCEPTION during recovery: %r" % (exc,))

    trips_clean = (not tripwire_read_attempts) and (not tripwire_import_attempts)
    sha_ok = bool(wire_pin) and folded == wire_pin
    bytes_ok = member_bytes is not None and count == member_bytes
    green = sha_ok and bytes_ok and trips_clean and not failure_notes
    if not green:
        if wire_pin and folded and folded != wire_pin:
            failure_notes.append("streamed sha256 %s != wire pin %s"
                                 % (folded, wire_pin))
        if member_bytes is not None and count != member_bytes:
            failure_notes.append("streamed byte count %s != member_bytes %s"
                                 % (count, member_bytes))
        if not trips_clean:
            failure_notes.append("tripwires fired: reads=%d imports=%d"
                                 % (len(tripwire_read_attempts),
                                    len(tripwire_import_attempts)))
        if not failure_notes:
            failure_notes.append("recovery incomplete")

    impl_sha = sha256_of_file(os.path.abspath(__file__))

    receipt = {
        "independent_non_author": bool(green),
        "provenance_mode": "claude_agent_clean_room",
        "external_session_id": session_id,
        "public_repository": "https://github.com/keithkallison-ai/mera-az",
        "public_commit": "pending-push",
        "inputs_permitted": [
            "http://127.0.0.1:8821/api/manifest",
            "http://127.0.0.1:8821/api/source/<tag16>",
        ],
        "tripwire_import_attempts": list(tripwire_import_attempts),
        "tripwire_read_attempts": list(tripwire_read_attempts),
        "input_closure_held": trips_clean,
        "source": SOURCE_ID,
        "folded_sha256": folded,
        "bytes_verified": count,
        "wire_pin_sha256": wire_pin,
        "equivalence_level": "L_byte, whole document, recovered from the wire alone under enforced closure",
        "does_NOT_prove": [
            "publisher fidelity — link 1 is a separate anchor",
            "spec-sufficiency for reconstruction from typed surfaces — a spec-emit commission is the stronger form and remains open",
            "anything about other sources",
        ],
        "utc": datetime.now(timezone.utc).isoformat(),
        "implementation_sha256": impl_sha,
    }
    if not green:
        receipt["failure"] = "; ".join(failure_notes)

    with open(RECEIPT_PATH, "w", encoding="utf-8", newline="\n") as f:
        json.dump(receipt, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(json.dumps({
        "green": green,
        "source": SOURCE_ID,
        "tag16": tag16,
        "folded_sha256": folded,
        "wire_pin_sha256": wire_pin,
        "bytes_verified": count,
        "member_bytes": member_bytes,
        "tripwire_read_attempts": len(tripwire_read_attempts),
        "tripwire_import_attempts": len(tripwire_import_attempts),
        "external_session_id": session_id,
        "receipt": RECEIPT_PATH,
    }))
    return 0 if green else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(selftest())
    sys.exit(main())
