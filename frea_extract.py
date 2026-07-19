"""
FREA / COBRA asset extractor for Elite Dangerous Odyssey
========================================================

Extracts the decodable content of every file under ``Win64/{00..0f}/{sha1}``.

Unlike the original version, this handles ALL three file kinds found in the
data set (see ``frea_core`` for the full write-up):

    FREA  - RSA-2048 + AES-256-ECB encrypted COBRA package (has a name table)
    zlib  - raw 78 9c zlib stream (loose COBRA resource blob, hash-named)
    RIFF  - raw WAV audio

For every asset it writes ``<output>/<subdir>/<name>__<sha1_8>.<ext>`` where:
    .cobra  decompressed COBRA payload (FREA + zlib kinds)
    .wav    RIFF audio
    .bin    anything else (passed through)

Named FREA packages additionally get a ``.manifest.txt`` describing the
contained resources as a folder tree (the dotted asset names), and an
``index.csv`` is written at the root mapping sha1 -> name/kind/type/sizes.

Usage:
    python frea_extract.py [--output DIR] [--all] [--max N]
                           [--game DIR] [--kinds FREA,zlib,RIFF,raw]
                           [--manifests/--no-manifests] [--envelopes] [-v]
"""

import os
import sys
import csv
import argparse
from pathlib import Path

import frea_core as fc

GAME_DIR_DEFAULTS = [
    r'F:\SteamLibrary\steamapps\common\Elite Dangerous\Products\elite-dangerous-odyssey-64',
    r'C:\Program Files (x86)\Steam\steamapps\common\Elite Dangerous\Products\elite-dangerous-odyssey-64',
    r'D:\SteamLibrary\steamapps\common\Elite Dangerous\Products\elite-dangerous-odyssey-64',
]

EXT_BY_KIND = {fc.KIND_FREA: '.cobra', fc.KIND_ZLIB: '.cobra',
               fc.KIND_RIFF: '.wav', fc.KIND_RAW: '.bin'}


def find_game_dir(explicit):
    if explicit:
        return Path(explicit)
    for d in GAME_DIR_DEFAULTS:
        # Only the Win64 asset tree is required; the binary is optional (key is baked in).
        if (Path(d) / 'Win64').is_dir():
            return Path(d)
    return None


def render_tree(tree, indent=0):
    lines = []
    for key in sorted(tree):
        lines.append('  ' * indent + '- ' + key)
        lines.extend(render_tree(tree[key], indent + 1))
    return lines


def write_manifest(path, asset):
    lines = [
        f"package : {asset.primary_name}",
        f"sha1    : {asset.sha1}",
        f"kind    : {asset.kind}",
        f"type    : {asset.type_desc} ({asset.category})",
        f"type tag: {asset.type_tag}",
        f"payload : {asset.payload_size:,} bytes",
        f"contained resources ({len(asset.names)}):",
    ]
    lines.extend('  ' + ln for ln in render_tree(asset.tree))
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    ap = argparse.ArgumentParser(description="FREA/COBRA extractor for Elite Dangerous Odyssey")
    ap.add_argument('--output', '-o', default='./extracted')
    ap.add_argument('--game', help="Path to elite-dangerous-odyssey-64 folder")
    ap.add_argument('--all', action='store_true', help="Extract every file")
    ap.add_argument('--max', type=int, default=40, help="Max files when not --all")
    ap.add_argument('--kinds', default='', help="Comma list filter: FREA,zlib,RIFF,raw")
    ap.add_argument('--manifests', dest='manifests', action='store_true', default=True)
    ap.add_argument('--no-manifests', dest='manifests', action='store_false')
    ap.add_argument('--envelopes', action='store_true', help="Also dump FREA envelope headers")
    ap.add_argument('--verbose', '-v', action='store_true')
    args = ap.parse_args()

    game = find_game_dir(args.game)
    if not game or not (game / 'Win64').is_dir():
        print("ERROR: could not find a Win64 asset directory. Use --game to point "
              "at the elite-dangerous-odyssey-64 folder (or one containing Win64).")
        return 2
    win64 = game / 'Win64'
    binary = game / 'EliteDangerous64.exe'

    print(f"Game: {game}")
    # The RSA public key is baked in, so no binary is needed. If the binary
    # happens to be present, extract from it to catch a future key change.
    if binary.exists():
        try:
            rsa = fc.load_rsa_key(binary)
        except Exception as ex:
            print(f"  (binary key load failed: {ex}; using baked-in key)")
            rsa = fc.default_rsa_key()
    else:
        rsa = fc.default_rsa_key()
    print(f"RSA pubkey: {rsa.n.bit_length()}-bit, E={rsa.e}")

    kind_filter = {k.strip() for k in args.kinds.split(',') if k.strip()} or None

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    index_path = out / 'index.csv'
    idx = open(index_path, 'w', newline='', encoding='utf-8')
    writer = csv.writer(idx)
    writer.writerow(['subdir', 'sha1', 'kind', 'category', 'type', 'primary_name',
                     'num_resources', 'file_size', 'payload_size', 'out_file', 'error'])

    stats = {'total': 0, 'ok': 0, 'err': 0, 'FREA': 0, 'zlib': 0, 'RIFF': 0, 'raw': 0,
             'named': 0, 'bytes': 0}
    limit = None if args.all else args.max

    for subdir, sha1, fp in fc.iter_asset_files(win64):
        if limit is not None and stats['total'] >= limit:
            break
        stats['total'] += 1
        try:
            data = fp.read_bytes()
        except OSError as ex:
            stats['err'] += 1
            writer.writerow([subdir, sha1, '', '', '', '', 0, 0, 0, '', str(ex)])
            continue

        asset = fc.open_asset(data, sha1, rsa, subdir)
        if kind_filter and asset.kind not in kind_filter:
            stats['total'] -= 1
            continue
        stats[asset.kind] = stats.get(asset.kind, 0) + 1

        out_file = ''
        if asset.ok and asset.payload is not None:
            sub_out = out / subdir
            sub_out.mkdir(parents=True, exist_ok=True)
            base = (f"{fc.safe_filename(asset.primary_name, 80)}__{sha1[:8]}"
                    if asset.is_named else sha1)
            ext = EXT_BY_KIND.get(asset.kind, '.bin')
            target = sub_out / f"{base}{ext}"
            target.write_bytes(asset.payload)
            out_file = str(target.relative_to(out))
            stats['ok'] += 1
            stats['bytes'] += asset.payload_size
            if asset.is_named:
                stats['named'] += 1
                if args.manifests:
                    write_manifest(sub_out / f"{base}.manifest.txt", asset)
            if args.envelopes and asset.kind == fc.KIND_FREA and asset.zlib_off > 0:
                (sub_out / f"{base}.envelope").write_bytes(asset.decrypted[:asset.zlib_off])
        else:
            stats['err'] += 1
            if args.verbose:
                print(f"[!] {subdir}/{sha1[:12]} ({asset.kind}): {asset.error}")

        writer.writerow([subdir, sha1, asset.kind, asset.category, asset.type_desc,
                         asset.primary_name, len(asset.names), asset.file_size,
                         asset.payload_size, out_file, asset.error or ''])

        if stats['total'] % 500 == 0:
            print(f"  ...{stats['total']:,} processed (ok={stats['ok']:,} err={stats['err']})")

    idx.close()
    print("\n=== Results ===")
    print(f"  Files processed : {stats['total']:,}")
    print(f"  Decoded OK      : {stats['ok']:,}")
    print(f"  Errors          : {stats['err']:,}")
    print(f"  By kind         : FREA={stats['FREA']:,}  zlib={stats['zlib']:,}  "
          f"RIFF={stats['RIFF']:,}  raw={stats['raw']:,}")
    print(f"  Named packages  : {stats['named']:,}")
    print(f"  Payload written : {fc.fmt_size(stats['bytes'])}")
    print(f"  Output          : {out}")
    print(f"  Index           : {index_path}")
    return 0 if stats['ok'] > 0 else 1


if __name__ == '__main__':
    sys.exit(main())
