#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
kpic-co CLEAN-ROOM EMITTER — non-authorship commission.

Written from scratch, solely from:
  1. the serve's own HTTP responses at http://127.0.0.1:8812/v1/kpic-co/*
  2. emitter_contract.json  (read-only, the published emitter grammar)
  3. emitter_vectors.json   (read-only, 9 pinned (input -> expected bytes) vectors)

It rebuilds the whole document from the serve's structure columns
(parent_raw_start / sibling_seq / object_key_token_b64 / array_ordinal /
 present_state / json_type / value_token_b64) streamed in raw_start order
(the serve declares order=["raw_start"], order_unique_proven=true, which is
document preorder), emits bytes per the published grammar, and folds them to
ONE sha256 — the member is never written to disk, only hashed.

GRAMMAR (derived from the contract + vectors, nothing else):
  - TAB indent, one tab per level; LF newlines; no trailing newline.
  - object: "{" NL, members each on their own line as <tabs>"key": value,
    separated by "," NL, closed by NL <tabs> "}". Empty object -> EMPTY_OBJECT
    constant ("{}", explicit branch — NOT OBSERVED in this member).
  - array of objects: "[" then member objects separated by "," (the "},{"
    seam), "]" directly after the last "}"; object members render one level
    deeper, closing braces at the array's own member depth.
  - scalar array: inline "[a, b, c]", elements joined by ", "; WRAP RULE:
    the array breaks to a new physical line (",\\n" + one-deeper tabs) when
    the ACCUMULATED ELEMENT TEXT on the current line (element tokens plus the
    ", " separators BETWEEN them) would exceed WRAP_BUDGET; the indent and
    the trailing comma are NOT counted.  Pinned from both sides by the
    wrap-just-under / wrap-just-over vectors.
  - empty array -> EMPTY_ARRAY constant ("[ ]", observed: with a space).
  - leaf tokens (strings, numbers, booleans, null) and object-key tokens are
    the VERBATIM source tokens (base64 columns), emitted as-is — number
    spellings and string escapes survive untouched.
Unobserved constructs (array-of-arrays, mixed arrays, container-array with
zero children) RAISE — an unobserved branch is never allowed to silently
default.

VERIFICATION SPINE: every row carries raw_start/raw_end; the emitter asserts
its own output offset equals raw_start at the instant each node's value
begins, and raw_end when it closes. A grammar divergence therefore localises
to the exact occurrence, without any raw route. The fold is GREEN only if
sha256 == member_sha256 (contract pin) over exactly member_bytes bytes.

INPUT CLOSURE (enforced in code, armed before the first data read):
  - open()/io.open/os.open guard: any path outside C:/Temp/gs_commission_kpic
    other than the two read-only contract files RAISES and is recorded in
    tripwire_read_attempts.
  - sys.meta_path import guard: any module whose origin lies under
    C:/Users/keith/Payer RAISES and is recorded in tripwire_import_attempts.
  - HTTP to 127.0.0.1:8812 is the only data channel.
"""

# --- ALL imports up-front: after the guards arm, no new module may be loaded ---
import sys
import os
import io
import json
import time
import base64
import hashlib
import uuid
import datetime
import argparse
import socket
import http.client
import builtins
import linecache  # pre-imported and neutered so error paths never open stdlib sources

WORKDIR = "C:/Temp/gs_commission_kpic"
CONTRACT_PATH = "C:/Users/keith/Payer/Outposts/Kaiser/serve_lossless/emitter_contract.json"
VECTORS_PATH = "C:/Users/keith/Payer/Outposts/Kaiser/serve_lossless/emitter_vectors.json"
PAYER_ROOT = "C:/Users/keith/Payer"
HOST, PORT = "127.0.0.1", 8812
ROUTE = "/v1/kpic-co/source/occurrences"
PAGE_LIMIT = 5000  # serve maximum (probed: "limit must be 1..5000 (no silent caps)")

COMMISSION_SHA = "b697ff34c3c806eda96a2363aeb55787b9f8b9d80a7d386ecc162de3984e71e1"
COMMISSION_BYTES = 384622330

tripwire_read_attempts = []
tripwire_import_attempts = []

# ----------------------------------------------------------------- guards ---

def _norm(p):
    return os.path.normcase(os.path.abspath(p))

_ALLOWED_DIR = _norm(WORKDIR) + os.sep
_ALLOWED_RO = {_norm(CONTRACT_PATH), _norm(VECTORS_PATH)}
_PAYER_PREFIX = _norm(PAYER_ROOT) + os.sep

_real_open = builtins.open
_real_io_open = io.open
_real_os_open = os.open

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC


def _path_allowed(file, write_intent):
    if isinstance(file, int):  # pre-existing fd: no new path is being opened
        return True
    try:
        p = _norm(os.fspath(file))
    except TypeError:
        return False
    if p.startswith(_ALLOWED_DIR):
        return True
    if p in _ALLOWED_RO:
        return not write_intent  # the two contract files are READ-ONLY
    return False


def _guarded(real, api):
    def call(file, mode="r", *a, **k):
        write_intent = any(c in str(mode) for c in "wax+")
        if not _path_allowed(file, write_intent):
            tripwire_read_attempts.append({"api": api, "path": str(file), "mode": str(mode)})
            raise PermissionError("input-closure: refused %s(%r, %r)" % (api, file, mode))
        return real(file, mode, *a, **k)
    return call


def _guarded_os_open(path, flags, *a, **k):
    write_intent = bool(flags & _WRITE_FLAGS)
    if not _path_allowed(path, write_intent):
        tripwire_read_attempts.append({"api": "os.open", "path": str(path), "flags": int(flags)})
        raise PermissionError("input-closure: refused os.open(%r, %#x)" % (path, flags))
    return _real_os_open(path, flags, *a, **k)


class _ImportGuard:
    """meta_path hook: refuse any module whose origin lies under the Payer repo."""

    def find_spec(self, name, path=None, target=None):
        for finder in sys.meta_path:
            if finder is self:
                continue
            find = getattr(finder, "find_spec", None)
            if find is None:
                continue
            try:
                spec = find(name, path, target)
            except ImportError:
                spec = None
            if spec is not None:
                origin = getattr(spec, "origin", None)
                if isinstance(origin, str) and _norm(origin).startswith(_PAYER_PREFIX):
                    tripwire_import_attempts.append({"module": name, "origin": origin})
                    raise ImportError("input-closure: refused import %r from %r" % (name, origin))
                return None  # benign: let the normal machinery resolve it
        return None


_GUARDS_ARMED = False


def arm_guards():
    global _GUARDS_ARMED
    linecache.getline = lambda *a, **k: ""      # error paths must never open sources
    linecache.getlines = lambda *a, **k: []
    linecache.checkcache = lambda *a, **k: None
    builtins.open = _guarded(_real_open, "open")
    io.open = _guarded(_real_io_open, "io.open")
    os.open = _guarded_os_open
    sys.meta_path.insert(0, _ImportGuard())
    _GUARDS_ARMED = True


# ---------------------------------------------------------------- emitter ---

class EmitError(Exception):
    pass


class Sink:
    """sha256 + byte counter; the document is folded, never persisted."""

    __slots__ = ("h", "n", "_buf", "_blen")

    def __init__(self):
        self.h = hashlib.sha256()
        self.n = 0
        self._buf = []
        self._blen = 0

    def write(self, b):
        self._buf.append(b)
        self._blen += len(b)
        self.n += len(b)
        if self._blen >= (1 << 20):
            self.h.update(b"".join(self._buf))
            self._buf = []
            self._blen = 0

    def hexdigest(self):
        if self._buf:
            self.h.update(b"".join(self._buf))
            self._buf = []
            self._blen = 0
        return self.h.hexdigest()


# frame indices
F_KEY, F_KIND, F_D, F_N, F_MODE, F_ACC, F_END = range(7)
K_MAP, K_ARR = 0, 1
M_UNSET, M_SCALAR, M_MAP = 0, 1, 2

_SCALAR_TYPES = frozenset(("string", "number", "boolean", "null"))


class Emitter:
    """Streaming preorder emitter. feed() consumes one occurrence row (dict with
    parent_raw_start / sibling_seq / object_key_token_b64 / array_ordinal /
    present_state / json_type / value_token_b64 / raw_start / raw_end);
    finish() closes every open container."""

    def __init__(self, sink, wrap_budget, empty_array, empty_object, check_offsets=True):
        self.sink = sink
        self.wrap = wrap_budget
        self.empty_array = empty_array
        self.empty_object = empty_object
        self.co = check_offsets
        self.stack = []
        self.rows = 0
        self._tabs = [b"", b"\t"]

    def tabs(self, d):
        t = self._tabs
        while len(t) <= d:
            t.append(t[-1] + b"\t")
        return t[d]

    def _close(self, f):
        w = self.sink.write
        if f[F_KIND] == K_MAP:
            if f[F_N] == 0:
                w(self.empty_object)  # explicit EMPTY_OBJECT branch (unobserved in member)
            else:
                w(b"\n")
                w(self.tabs(f[F_D]))
                w(b"}")
        else:
            if f[F_MODE] == M_UNSET:
                raise EmitError("container array with zero children at raw_start=%r "
                                "(contract says empty arrays are present_state=empty_array)" % f[F_KEY])
            w(b"]")
        if self.co and f[F_END] is not None and self.sink.n != f[F_END]:
            raise EmitError("close offset mismatch: node raw_start=%r expected raw_end=%d got %d"
                            % (f[F_KEY], f[F_END], self.sink.n))

    def feed(self, row):
        self.rows += 1
        sink = self.sink
        w = sink.write
        stack = self.stack

        parent = row["parent_raw_start"]
        raw_start = row["raw_start"]
        raw_end = row["raw_end"]
        state = row["present_state"]
        jtype = row["json_type"]

        # 1. close containers until the parent is on top
        if parent == -1:
            if stack:
                raise EmitError("second root at raw_start=%r" % raw_start)
            if state != "container" or jtype != "map":
                raise EmitError("root must be a container map, got %s/%s" % (state, jtype))
            stack.append([raw_start, K_MAP, 0, 0, M_UNSET, 0, raw_end])
            if self.co and raw_start != 0:
                raise EmitError("root raw_start=%r != 0" % raw_start)
            return

        while stack and stack[-1][F_KEY] != parent:
            self._close(stack.pop())
        if not stack:
            raise EmitError("orphan row raw_start=%r parent=%r not on stack (order violation)"
                            % (raw_start, parent))
        f = stack[-1]

        key_b64 = row["object_key_token_b64"]
        ordinal = row["array_ordinal"]
        seq = row["sibling_seq"]
        if seq != f[F_N]:
            raise EmitError("sibling_seq %r != expected %r at raw_start=%r" % (seq, f[F_N], raw_start))

        if f[F_KIND] == K_MAP:
            # ---- object member: <tabs>"key": value
            if ordinal != -1:
                raise EmitError("map member with array_ordinal=%r at raw_start=%r" % (ordinal, raw_start))
            if key_b64 is None:
                raise EmitError("map member missing key token at raw_start=%r" % raw_start)
            w(b"{\n" if f[F_N] == 0 else b",\n")
            w(self.tabs(f[F_D] + 1))
            w(base64.b64decode(key_b64))
            w(b": ")
            f[F_N] += 1
            d = f[F_D] + 1
            if self.co and sink.n != raw_start:
                raise EmitError("value offset mismatch at raw_start=%d (emitted %d) key=%r"
                                % (raw_start, sink.n, base64.b64decode(key_b64)[:60]))
            if state == "value":
                if jtype not in _SCALAR_TYPES:
                    raise EmitError("present_state=value with json_type=%r at raw_start=%r" % (jtype, raw_start))
                tok = base64.b64decode(row["value_token_b64"])
                w(tok)
                if self.co and sink.n != raw_end:
                    raise EmitError("leaf raw_end mismatch at raw_start=%d" % raw_start)
            elif state == "empty_array":
                if jtype != "array":
                    raise EmitError("empty_array with json_type=%r at raw_start=%r" % (jtype, raw_start))
                w(self.empty_array)
                if self.co and sink.n != raw_end:
                    raise EmitError("empty_array raw_end mismatch at raw_start=%d" % raw_start)
            elif state == "container":
                if jtype == "map":
                    stack.append([raw_start, K_MAP, d, 0, M_UNSET, 0, raw_end])  # "{" deferred
                elif jtype == "array":
                    w(b"[")
                    stack.append([raw_start, K_ARR, d, 0, M_UNSET, 0, raw_end])
                else:
                    raise EmitError("container with json_type=%r at raw_start=%r" % (jtype, raw_start))
            else:
                raise EmitError("unknown present_state=%r at raw_start=%r" % (state, raw_start))
            return

        # ---- array element
        if key_b64 is not None:
            raise EmitError("array element with a key token at raw_start=%r" % raw_start)
        if ordinal != f[F_N]:
            raise EmitError("array_ordinal %r != expected %r at raw_start=%r" % (ordinal, f[F_N], raw_start))

        if state == "value":
            if jtype not in _SCALAR_TYPES:
                raise EmitError("scalar element with json_type=%r at raw_start=%r" % (jtype, raw_start))
            tok = base64.b64decode(row["value_token_b64"])
            if f[F_N] == 0:
                f[F_MODE] = M_SCALAR
                w(tok)
                f[F_ACC] = len(tok)
            else:
                if f[F_MODE] != M_SCALAR:
                    raise EmitError("mixed array (container then scalar) at raw_start=%r" % raw_start)
                cand = f[F_ACC] + 2 + len(tok)
                if cand > self.wrap:
                    # trailing comma ends the line (not counted); indent not counted
                    w(b",\n")
                    w(self.tabs(f[F_D] + 1))
                    w(tok)
                    f[F_ACC] = len(tok)
                else:
                    w(b", ")
                    w(tok)
                    f[F_ACC] = cand
            f[F_N] += 1
            if self.co and sink.n != raw_end:
                raise EmitError("scalar element raw_end mismatch at raw_start=%d (emitted %d)"
                                % (raw_start, sink.n))
            return

        if state == "container" and jtype == "map":
            if f[F_N] == 0:
                f[F_MODE] = M_MAP
            else:
                if f[F_MODE] != M_MAP:
                    raise EmitError("mixed array (scalar then container) at raw_start=%r" % raw_start)
                w(b",")  # the "},{" seam: previous "}" was written on close
            f[F_N] += 1
            if self.co and sink.n != raw_start:
                raise EmitError("array-member offset mismatch at raw_start=%d (emitted %d)"
                                % (raw_start, sink.n))
            stack.append([raw_start, K_MAP, f[F_D], 0, M_UNSET, 0, raw_end])  # "{" deferred
            return

        # everything else is UNOBSERVED in this member: raise, never default
        raise EmitError("unobserved construct in array at raw_start=%r: state=%r json_type=%r"
                        % (raw_start, state, jtype))

    def finish(self):
        while self.stack:
            self._close(self.stack.pop())


# NOTE on the array "[": it is written when the ARRAY VALUE itself is fed
# (state=container/json_type=array under a map parent). The first SCALAR
# element then lands directly after "[" — its raw_start assert proves it.
# For array-of-maps the child map's "{" is deferred to its own first member,
# giving "[{" ... "},{" ... "}]" exactly as the nested-array-of-objects
# vector pins.


# ------------------------------------------------------------ vector rig ---

def _vector_token(v):
    """Vector inputs are parsed JSON; regenerate their (trivial) source tokens.
    The 9 vectors contain only ints and escape-free strings, so this mapping is
    exact for the vectors; the REAL run always uses the serve's verbatim
    base64 tokens and never touches this function."""
    if v is True:
        return b"true"
    if v is False:
        return b"false"
    if v is None:
        return b"null"
    if isinstance(v, str):
        return b'"' + v.encode("utf-8") + b'"'
    if isinstance(v, int):
        return str(v).encode("ascii")
    raise EmitError("vector adapter: unsupported scalar %r" % (v,))


def _obj_to_rows(obj):
    """DFS-preorder rows for a vector input, shaped like serve rows (fake ids,
    offsets disabled)."""
    rows = []
    counter = [0]

    def add(parent, seq, key_tok, ordinal, value):
        nid = counter[0]
        counter[0] += 1
        base = {"parent_raw_start": parent, "sibling_seq": seq, "array_ordinal": ordinal,
                "object_key_token_b64": (base64.b64encode(key_tok).decode("ascii")
                                         if key_tok is not None else None),
                "raw_start": nid, "raw_end": None, "value_token_b64": None}
        if isinstance(value, dict):
            base["present_state"], base["json_type"] = "container", "map"
            rows.append(base)
            for i, (k, v) in enumerate(value.items()):
                add(nid, i, b'"' + k.encode("utf-8") + b'"', -1, v)
        elif isinstance(value, list):
            if not value:
                base["present_state"], base["json_type"] = "empty_array", "array"
                rows.append(base)
            else:
                base["present_state"], base["json_type"] = "container", "array"
                rows.append(base)
                for i, v in enumerate(value):
                    add(nid, i, None, i, v)
        else:
            base["present_state"] = "value"
            base["json_type"] = ("string" if isinstance(value, str) else
                                 "boolean" if isinstance(value, bool) else
                                 "null" if value is None else "number")
            base["value_token_b64"] = base64.b64encode(_vector_token(value)).decode("ascii")
            rows.append(base)

    if not isinstance(obj, dict):
        raise EmitError("vector root must be an object")
    add(-1, 0, None, -1, obj)
    return rows


def run_vectors(vectors_doc, wrap_budget, empty_array, empty_object):
    passed, failures = 0, []
    vecs = vectors_doc["vectors"]
    for vec in vecs:
        sink = Sink()
        em = Emitter(sink, wrap_budget, empty_array, empty_object, check_offsets=False)
        try:
            for row in _obj_to_rows(vec["input"]):
                em.feed(row)
            em.finish()
        except EmitError as e:
            failures.append("%s: EmitError %s" % (vec["name"], e))
            continue
        got_n = sink.n
        got_sha = sink.hexdigest()
        exp = vec["expected_utf8"].encode("utf-8")
        exp_sha = vec["expected_sha256"]
        if got_sha == exp_sha and got_n == vec["expected_bytes"] and got_n == len(exp):
            passed += 1
        else:
            failures.append("%s: got sha=%s bytes=%d expected sha=%s bytes=%d"
                            % (vec["name"], got_sha, got_n, exp_sha, vec["expected_bytes"]))
    return passed, len(vecs), failures


# ------------------------------------------------------------ serve pager ---

class Pager:
    def __init__(self):
        self.conn = None
        self.snapshot = None
        self.document_id = None
        self.total_rows = None
        self.pages = 0

    def _get(self, path):
        last = None
        for attempt in range(6):
            try:
                if self.conn is None:
                    self.conn = http.client.HTTPConnection(HOST, PORT, timeout=180)
                self.conn.request("GET", path)
                r = self.conn.getresponse()
                body = r.read()
                if r.status != 200:
                    raise RuntimeError("HTTP %d on %s: %s" % (r.status, path[:80], body[:200]))
                return json.loads(body.decode("utf-8"))
            except Exception as e:  # noqa: BLE001 — retried, then re-raised
                last = e
                try:
                    if self.conn is not None:
                        self.conn.close()
                except Exception:
                    pass
                self.conn = None
                time.sleep(min(2 ** attempt, 15))
        raise RuntimeError("pager: giving up on %s after retries: %r" % (path[:120], last))

    def rows(self, max_pages=None):
        base = "%s?limit=%d" % (ROUTE, PAGE_LIMIT)
        cursor = None
        seen_cursors = set()
        while True:
            path = base if cursor is None else base + "&cursor=" + cursor
            d = self._get(path)
            if self.snapshot is None:
                self.snapshot = d["serve_snapshot_id"]
                self.document_id = d.get("document_id")
                self.total_rows = d["total_rows"]
            elif d["serve_snapshot_id"] != self.snapshot:
                raise RuntimeError("serve snapshot rotated mid-run: %s -> %s"
                                   % (self.snapshot, d["serve_snapshot_id"]))
            self.pages += 1
            for row in d["rows"]:
                yield row
            if max_pages is not None and self.pages >= max_pages:
                return
            if not d.get("has_more"):
                return
            cursor = d["next_cursor"]
            if cursor in seen_cursors:
                raise RuntimeError("cursor repeated — paging is not advancing")
            seen_cursors.add(cursor)


# ------------------------------------------------------------------ main ----

def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path):
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=1)
        fh.write("\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors-only", action="store_true")
    ap.add_argument("--max-pages", type=int, default=None,
                    help="smoke run: stop after N pages (no receipt, no fold verdict)")
    args = ap.parse_args()

    session_path = os.path.join(WORKDIR, "session.json")
    if os.path.exists(session_path):
        session = json.loads(_real_open(session_path, "rb").read().decode("utf-8"))
    else:
        session = {"external_session_id": str(uuid.uuid4()), "minted_utc": utc_now()}
        with _real_open(session_path, "w", encoding="utf-8") as fh:
            json.dump(session, fh)
    session_id = session["external_session_id"]

    # ---- ARM THE INPUT CLOSURE (before the first data read) ----
    arm_guards()

    contract = load_json(CONTRACT_PATH)      # via the guard's read-only exception
    vectors_doc = load_json(VECTORS_PATH)    # via the guard's read-only exception

    consts = contract["constants"]
    wrap_budget = consts["WRAP_BUDGET"]
    empty_array = consts["EMPTY_ARRAY"].encode("utf-8")
    empty_object = consts["EMPTY_OBJECT"].encode("utf-8")
    member_sha = contract["member_sha256"]
    member_bytes = contract["member_bytes"]
    if vectors_doc["constants"] != consts:
        raise RuntimeError("contract/vectors constants disagree")
    if member_sha != COMMISSION_SHA or member_bytes != COMMISSION_BYTES:
        raise RuntimeError("contract pin differs from the commission pin")

    vpassed, vtotal, vfail = run_vectors(vectors_doc, wrap_budget, empty_array, empty_object)
    print("vectors: %d/%d" % (vpassed, vtotal), flush=True)
    for f in vfail:
        print("  VECTOR-FAIL", f, flush=True)

    if args.vectors_only:
        return 0 if vpassed == vtotal else 1
    if vpassed != vtotal:
        print("aborting before serve run: vectors not green", flush=True)
        return 1

    sink = Sink()
    em = Emitter(sink, wrap_budget, empty_array, empty_object, check_offsets=True)
    pager = Pager()
    t0 = time.time()
    progress_path = os.path.join(WORKDIR, "progress.json")
    failure = None
    try:
        for row in pager.rows(max_pages=args.max_pages):
            em.feed(row)
            if em.rows % 500000 == 0:
                el = time.time() - t0
                eta = el / em.rows * (pager.total_rows - em.rows)
                print("rows %d/%d bytes %d elapsed %.0fs eta %.0fs"
                      % (em.rows, pager.total_rows, sink.n, el, eta), flush=True)
                try:
                    write_json(progress_path, {"rows": em.rows, "total_rows": pager.total_rows,
                                               "bytes": sink.n, "elapsed_s": round(el, 1),
                                               "eta_s": round(eta, 1), "utc": utc_now()})
                except Exception:
                    pass
        if args.max_pages is None:
            em.finish()
    except (EmitError, RuntimeError) as e:
        failure = str(e)

    elapsed = time.time() - t0

    if args.max_pages is not None:
        print("SMOKE: pages=%d rows=%d emitted_bytes=%d offsets_ok=%s failure=%r elapsed=%.1fs"
              % (pager.pages, em.rows, sink.n, failure is None, failure, elapsed), flush=True)
        return 0 if failure is None else 1

    folded = sink.hexdigest() if failure is None else None
    nbytes = sink.n
    closure_held = (not tripwire_read_attempts) and (not tripwire_import_attempts) and _GUARDS_ARMED
    green = (failure is None and folded == member_sha and nbytes == member_bytes
             and vpassed == vtotal and closure_held)

    receipt = {
        "independent_non_author": bool(green),
        "provenance_mode": "claude_agent_clean_room",
        "external_session_id": session_id,
        "public_repository": "https://github.com/keithkallison-ai/mera-az",
        "public_commit": "PENDING_PUBLICATION",
        "inputs_permitted": [
            "http://127.0.0.1:8812/v1/kpic-co/* (HTTP GET only)",
            "C:\\Users\\keith\\Payer\\Outposts\\Kaiser\\serve_lossless\\emitter_contract.json (read-only)",
            "C:\\Users\\keith\\Payer\\Outposts\\Kaiser\\serve_lossless\\emitter_vectors.json (read-only)",
        ],
        "tripwire_import_attempts": list(tripwire_import_attempts),
        "tripwire_read_attempts": list(tripwire_read_attempts),
        "input_closure_held": bool(closure_held),
        "source": "kpic-co",
        "folded_sha256": folded,
        "bytes_verified": nbytes,
        "vectors_passed": "%d/9" % vpassed,
        "equivalence_level": "L_byte over the whole member, rebuilt from typed serve surfaces per the published contract",
        "does_NOT_prove": [
            "publisher fidelity — that is link 1, a separate anchor",
            "anything about sources other than kpic-co",
        ],
        "utc": utc_now(),
        "implementation_sha256": hashlib.sha256(open(os.path.join(WORKDIR, "emitter.py"), "rb").read()).hexdigest(),
    }
    if not green:
        receipt["independent_non_author"] = False
        receipt["failure"] = failure or (
            "folded sha/bytes mismatch: got %s over %d bytes" % (folded, nbytes))

    write_json(os.path.join(WORKDIR, "commission_kpic-co_receipt.json"), receipt)
    write_json(os.path.join(WORKDIR, "state.json"), {
        "green": bool(green), "folded_sha256": folded, "bytes": nbytes,
        "rows": em.rows, "pages": pager.pages, "total_rows": pager.total_rows,
        "serve_snapshot_id": pager.snapshot, "document_id": pager.document_id,
        "vectors": "%d/%d" % (vpassed, vtotal), "elapsed_s": round(elapsed, 1),
        "failure": failure, "utc": utc_now(),
    })
    print("VERDICT: %s folded=%s bytes=%d rows=%d elapsed=%.1fs closure_held=%s"
          % ("GREEN" if green else "NOT-GREEN", folded, nbytes, em.rows, elapsed, closure_held),
          flush=True)
    return 0 if green else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as e:  # terse, source-free error report
        tb = e.__traceback__
        chain = []
        while tb is not None:
            chain.append("%s:%d:%s" % (os.path.basename(tb.tb_frame.f_code.co_filename),
                                       tb.tb_lineno, tb.tb_frame.f_code.co_name))
            tb = tb.tb_next
        print("FATAL %s: %s | %s" % (type(e).__name__, str(e)[:600], " > ".join(chain)), flush=True)
        sys.exit(2)
