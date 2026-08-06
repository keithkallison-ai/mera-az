# -*- coding: utf-8 -*-
"""S5/U3 — STRANGER MACHINERY: per-source RFC 6962 Merkle roots over the served rows, and a
verifier that needs NOTHING from us but one row, one path, and a published root.

Ported from `Outposts/Hospital/universal_serve/merkle_root.py` (the class + its paid lessons:
0x00/0x01 domain prefixes; the doubled-tree_size mutant; index-decides-sides). NEVER a
combined root — one tree per (source × artifact): the federation partition rows bind every
byte-span of the document; the rates rail rows bind every typed price.

THE LEAF IS ONE SERVED ROW: the raw jsonl line bytes (self-delimiting canonical JSON — the
row a consumer actually holds). Leaf ambiguity is impossible: one line, one row, no separator
to forge.

⛔⛔ SIDE B ONLY. An inclusion proof proves MEMBERSHIP — that the row you hold is in the
release we published. It proves NOTHING about publisher fidelity (link-1 census owns that)
or serve losslessness (WIRE-12 owns that). A beautiful tree over wrong data verifies
perfectly. And these roots are UNSIGNED — non-repudiation is a separate deliberate step.

  python Workshop/GlobalServe/gs_merkle_roots.py --build
  python Workshop/GlobalServe/gs_merkle_roots.py --prove <sid> <partition|rates> <index>
  python Workshop/GlobalServe/gs_merkle_roots.py --verify <packet.json>
  python Workshop/GlobalServe/gs_merkle_roots.py --selftest
Receipt: gs_merkle_roots_receipt.json · packets: closure/gs_merkle_packet_*.json
"""
import argparse
import hashlib
import io
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
# ⛔ NO top-level lane import: --verify must run from a bare packet ANYWHERE (the outsider
# path died on ImportError when the published verifier was run outside the repo, 2026-08-04).
# Build/prove stamp receipts and import the registry LAZILY.

RECEIPT = os.path.join(HERE, 'gs_merkle_roots_receipt.json')
FED = os.path.join(HERE, 'cd0_federation.json')
RATES = os.path.join(HERE, 'gs_rates_index.json')


def mth_leaf(b):
    return hashlib.sha256(b'\x00' + b).digest()


def mth_node(l, r):
    return hashlib.sha256(b'\x01' + l + r).digest()


def _k(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root_of(hashes, lo=0, hi=None):
    hi = len(hashes) if hi is None else hi
    n = hi - lo
    if n == 0:
        return hashlib.sha256(b'').digest()
    if n == 1:
        return hashes[lo]
    k = _k(n)
    return mth_node(root_of(hashes, lo, lo + k), root_of(hashes, lo + k, hi))


def path_of(hashes, m, lo=0, hi=None):
    hi = len(hashes) if hi is None else hi
    n = hi - lo
    if n == 1:
        return []
    k = _k(n)
    if m - lo < k:
        return path_of(hashes, m, lo, lo + k) + [root_of(hashes, lo + k, hi)]
    return path_of(hashes, m, lo + k, hi) + [root_of(hashes, lo, lo + k)]


def verify_path(leaf_hash, index, tree_size, path):
    """THE STRANGER'S ENTIRE JOB — pure function of (leaf, index, size, path)."""
    if index >= tree_size:
        raise ValueError('index beyond tree_size')
    fn, sn, h = index, tree_size - 1, leaf_hash
    for p in path:
        if fn == sn or fn % 2 == 1:
            h = mth_node(p, h)
            while not (fn == 0 or fn % 2 == 1):
                fn >>= 1
                sn >>= 1
        else:
            h = mth_node(h, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError('path did not consume the tree — tree_size lied '
                         '(the doubled-size mutant, refused by design)')
    return h


def artifacts():
    """[(sid, kind, path)] for the 12×2 trees, from the envelopes (never hand-listed)."""
    fed = json.load(io.open(FED, encoding='utf-8'))
    rat = json.load(io.open(RATES, encoding='utf-8'))
    out = []
    for s in fed['sources']:
        out.append((s['id'], 'partition', s['partition']['partition_path']))
    for s in rat['sources']:
        out.append((s['id'], 'rates', s['rates_path']))
    return out


def leaf_hashes(path):
    """One streaming pass: leaf hashes + artifact sha256 + line count. O(leaves) RAM
    (32 B/leaf), never the artifact."""
    hs = []
    doc = hashlib.sha256()
    with open(path, 'rb') as f:
        for line in f:
            doc.update(line)
            hs.append(mth_leaf(line.rstrip(b'\r\n')))
    return hs, doc.hexdigest(), len(hs)


def build():
    per = {}
    t00 = time.time()
    for sid, kind, path in artifacts():
        t0 = time.time()
        hs, art_sha, n = leaf_hashes(path)
        root = root_of(hs)
        per.setdefault(sid, {})[kind] = {
            'root_sha256': root.hex(), 'tree_size': n,
            'artifact': path.replace('\\', '/'), 'artifact_sha256': art_sha,
            'seconds': round(time.time() - t0, 1),
        }
        print(f'  ROOT {sid:24s} {kind:9s} {n:>10,} leaves · {root.hex()[:16]} · '
              f'{time.time() - t0:.1f}s')
    import gs_registry
    rec = gs_registry.stamp({
        'receipt': 'GlobalServe S5/U3 per-source RFC 6962 roots (Side B: membership '
                   'machinery; NEVER a combined root)',
        'utc': __import__('datetime').datetime.now(
            __import__('datetime').timezone.utc).isoformat(),
        'tool_sha256': hashlib.sha256(
            io.open(os.path.abspath(__file__), 'rb').read()).hexdigest(),
        'trees': per, 'n_trees': sum(len(v) for v in per.values()),
        'passed': sum(len(v) for v in per.values()),
        'total': 2 * len({s for s, _, _ in artifacts()}),
        'all_green': sum(len(v) for v in per.values())
        == 2 * len({s for s, _, _ in artifacts()}),
        'build_seconds': round(time.time() - t00, 1),
        'leaf_law': 'leaf = raw jsonl line bytes (CR/LF stripped), 0x00-prefixed; '
                    'interior 0x01-prefixed (RFC 6962 §2.1)',
        'equivalence_level': 'MEMBERSHIP under SHA-256 (RFC 6962) per (source × artifact); '
                             'roots are UNSIGNED',
        'does_NOT_prove': [
            'publisher fidelity — link-1 census owns that',
            'serve losslessness — WIRE-12 owns that',
            'non-repudiation — the roots are unsigned; signing is a separate deliberate step',
            'anything about rows NOT in these two artifacts',
        ],
    })
    tmp = RECEIPT + '.tmp'
    with io.open(tmp, 'w', encoding='utf-8') as f:
        json.dump(rec, f, indent=1, sort_keys=True)
    os.replace(tmp, RECEIPT)
    print(f'\nS5/U3 ROOTS: {rec["n_trees"]} trees · {rec["build_seconds"]}s · receipt -> '
          f'{os.path.basename(RECEIPT)}')
    return 0


def prove(sid, kind, index):
    path = next(p for s, k, p in artifacts() if s == sid and k == kind)
    hs, art_sha, n = leaf_hashes(path)
    with open(path, 'rb') as f:
        for i, line in enumerate(f):
            if i == index:
                row = line.rstrip(b'\r\n')
                break
        else:
            raise SystemExit(f'index {index} beyond {n}')
    pkt = {
        'packet': 'GS stranger packet — verify with gs_merkle_roots.py --verify (or any '
                  'RFC 6962 implementation; leaf = 0x00||row_bytes, node = 0x01||l||r)',
        'source': sid, 'artifact_kind': kind, 'row_utf8': row.decode('utf-8'),
        'index': index, 'tree_size': n,
        'path_hex': [p.hex() for p in path_of(hs, index)],
        'root_sha256': root_of(hs).hex(),
    }
    out = os.path.join(HERE, 'closure', f'gs_merkle_packet_{sid}_{kind}_{index}.json')
    with io.open(out, 'w', encoding='utf-8') as f:
        json.dump(pkt, f, indent=1, sort_keys=True)
    print(f'PACKET -> {out}')
    return 0


def prove_batch(outdir):
    """One deterministic packet per (source × artifact) — index = tree_size // 2 — in a
    SINGLE leaf pass per artifact (24 separate --prove calls would re-stream the whale
    rail 41 s each; this is the U6 publication path)."""
    os.makedirs(outdir, exist_ok=True)
    n_out = 0
    for sid, kind, path in artifacts():
        hs, art_sha, n = leaf_hashes(path)
        idx = n // 2
        with open(path, 'rb') as f:
            for i, line in enumerate(f):
                if i == idx:
                    row = line.rstrip(b'\r\n')
                    break
        pkt = {
            'packet': 'GS stranger packet — verify with gs_merkle_roots.py --verify (or '
                      'any RFC 6962 implementation; leaf = SHA256(0x00||row_bytes), '
                      'node = SHA256(0x01||l||r))',
            'source': sid, 'artifact_kind': kind, 'row_utf8': row.decode('utf-8'),
            'index': idx, 'tree_size': n,
            'path_hex': [p.hex() for p in path_of(hs, idx)],
            'root_sha256': root_of(hs).hex(),
        }
        out = os.path.join(outdir, f'packet_{sid}_{kind}.json')
        with io.open(out, 'w', encoding='utf-8') as f:
            json.dump(pkt, f, indent=1, sort_keys=True)
        n_out += 1
        print(f'  PACKET {sid:24s} {kind:9s} row {idx:>9,}/{n:,}')
    print(f'{n_out} packets -> {outdir}')
    return 0


def verify(packet_path):
    """Reads ONLY the packet. No registry, no envelope, no artifact of ours."""
    pkt = json.load(io.open(packet_path, encoding='utf-8'))
    h = verify_path(mth_leaf(pkt['row_utf8'].encode('utf-8')), pkt['index'],
                    pkt['tree_size'], [bytes.fromhex(x) for x in pkt['path_hex']])
    ok = h.hex() == pkt['root_sha256']
    print(f'{"VERIFIED" if ok else "REFUSED"}  leaf {pkt["index"]}/{pkt["tree_size"]} vs '
          f'root {pkt["root_sha256"][:16]}')
    return 0 if ok else 1


def selftest():
    print('=== gs_merkle_roots --selftest: can the VERIFIER refuse? ===')
    sid, kind, path = artifacts()[0]
    hs = []
    rows = []
    with open(path, 'rb') as f:
        for i, line in enumerate(f):
            if i >= 64:
                break
            rows.append(line.rstrip(b'\r\n'))
            hs.append(mth_leaf(rows[-1]))
    root = root_of(hs)
    got = 0
    ok = verify_path(mth_leaf(rows[7]), 7, len(hs), path_of(hs, 7)) == root
    print(f'  {"OK" if ok else "<<< BROKEN"}  CONTROL: a true row verifies')
    # T1 — a doctored row must refuse
    t = verify_path(mth_leaf(rows[7] + b'X'), 7, len(hs), path_of(hs, 7)) != root
    got += t
    print(f'  {"REFUSED" if t else "<<< ACCEPTED"}  a doctored row')
    # T2 — the wrong index must refuse
    t = verify_path(mth_leaf(rows[7]), 8, len(hs), path_of(hs, 7)) != root
    got += t
    print(f'  {"REFUSED" if t else "<<< ACCEPTED"}  a wrong index')
    # T3 — a DOUBLED tree_size must refuse (the hospital lane's paid mutant)
    try:
        t = verify_path(mth_leaf(rows[7]), 7, len(hs) * 2, path_of(hs, 7)) != root
    except ValueError:
        t = True
    got += t
    print(f'  {"REFUSED" if t else "<<< ACCEPTED"}  a doubled tree_size')
    # T4 — a truncated path must refuse
    try:
        t = verify_path(mth_leaf(rows[7]), 7, len(hs), path_of(hs, 7)[:-1]) != root
    except ValueError:
        t = True
    got += t
    print(f'  {"REFUSED" if t else "<<< ACCEPTED"}  a truncated path')
    print(f'  {got}/4 + control — '
          f'{"VERIFIER HAS TEETH" if got == 4 and ok else "VERIFIER IS BLIND"}')
    return 0 if got == 4 and ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--prove', nargs=3, metavar=('SID', 'KIND', 'INDEX'))
    ap.add_argument('--prove-batch', metavar='OUTDIR')
    ap.add_argument('--verify')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()
    sys.stdout.reconfigure(line_buffering=True)
    if a.selftest:
        return selftest()
    if a.verify:
        return verify(a.verify)
    if a.prove_batch:
        return prove_batch(a.prove_batch)
    if a.prove:
        return prove(a.prove[0], a.prove[1], int(a.prove[2]))
    if a.build:
        return build()
    raise SystemExit('need --build, --prove, --verify or --selftest')


if __name__ == '__main__':
    sys.exit(main())
