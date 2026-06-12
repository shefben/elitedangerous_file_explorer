"""
frea_core.py - unified decoder for Elite Dangerous Odyssey Win64 asset files.
================================================================================

The files in ``Win64/{00..0f}/{sha1}`` are NOT all the same. A census of the
dataset shows three distinct kinds (plus the odd pass-through):

  KIND_FREA  ~52%  RSA-2048 + AES-256-ECB encrypted COBRA *package*.
                   Decrypted layout:
                       [name string-table] [record table] [zlib stream]
                   The name table holds the human asset names; dotted names
                   (``mat.pbasecolour_roughness_lod0``) describe a folder tree.
  KIND_ZLIB  ~46%  Raw ``78 9c`` zlib stream, NOT encrypted. Decompresses
                   directly to the same COBRA payload, but has NO name table -
                   these loose resource blobs are identified only by their SHA1
                   (their names live in the FREA packages that reference them).
  KIND_RIFF   <1%  Raw RIFF/WAVE audio, stored uncompressed.
  KIND_RAW         Anything else - returned verbatim.

This module is the single source of truth for decoding; both the CLI extractor
(``frea_extract.py``) and the GUI (``frea_explorer.py``) import it so the
parsing logic can never drift between them.

Reverse-engineered facts (see memory ``frea-file-format``):
  * FREA magic ``FREA\\x00\\x00`` (a few use ``FREE``), 256-byte RSA key block,
    then AES-256-ECB ciphertext (16-byte aligned).
  * RSA-2048 public key embedded in EliteDangerous64.exe at VA 0x144C624A0, E=3.
  * AES key = recovered[12:][4:36] XOR ascii(sha1)[:32]  (the recovered bytes
    are ~all zero, so the key effectively equals the filename's SHA1 ascii).
  * The zlib stream inside a decrypted FREA buffer can sit anywhere after the
    name+record tables - it must be located by scanning the whole buffer, not
    just the first kilobyte (the previous extractor's bug).
"""

import os
import re
import sys
import zlib
import struct
from dataclasses import dataclass, field
from pathlib import Path

try:
    import pefile
except ImportError:  # pragma: no cover
    os.system(f'"{sys.executable}" -m pip install pefile')
    import pefile

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:  # pragma: no cover
    os.system(f'"{sys.executable}" -m pip install cryptography')
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend


RSA_PUBKEY_VA = 0x144C624A0
RSA_PUBKEY_SIZE = 268
ZLIB_MAGICS = (b'\x78\x9c', b'\x78\xda', b'\x78\x01', b'\x78\x5e')

KIND_FREA = 'FREA'
KIND_ZLIB = 'zlib'
KIND_RIFF = 'RIFF'
KIND_RAW = 'raw'


# ----------------------------------------------------------------------------
# RSA public key
# ----------------------------------------------------------------------------

@dataclass
class RsaKey:
    n: int
    e: int


def load_rsa_key(binary_path):
    """Read & parse the RSA-2048 public key embedded in EliteDangerous64.exe."""
    pe = pefile.PE(str(binary_path), fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = RSA_PUBKEY_VA - image_base
    fa = None
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            off = rva - s.VirtualAddress
            if off < s.SizeOfRawData:
                fa = s.PointerToRawData + off
            break
    if fa is None:
        raise RuntimeError(f"RSA pubkey VA 0x{RSA_PUBKEY_VA:x} not in any section")
    with open(binary_path, 'rb') as f:
        f.seek(fa)
        der = f.read(RSA_PUBKEY_SIZE)
    n, e = _parse_rsa_der(der)
    return RsaKey(n, e)


def _parse_rsa_der(der):
    p = 0
    if der[p] != 0x30:
        raise ValueError("RSA pubkey: not an ASN.1 SEQUENCE")
    p += 1
    p += 1 + (der[p] & 0x7F) if der[p] & 0x80 else 1
    if der[p] != 0x02:
        raise ValueError("RSA pubkey: expected INTEGER for N")
    p += 1
    if der[p] & 0x80:
        ln = der[p] & 0x7F
        p += 1
        n_len = int.from_bytes(der[p:p + ln], 'big')
        p += ln
    else:
        n_len = der[p]
        p += 1
    n = int.from_bytes(der[p:p + n_len], 'big')
    p += n_len
    p += 1  # INTEGER tag for E
    e_len = der[p]
    p += 1
    e = int.from_bytes(der[p:p + e_len], 'big')
    return n, e


# ----------------------------------------------------------------------------
# Low-level decode primitives
# ----------------------------------------------------------------------------

def classify_kind(head):
    """Identify a file kind from its first bytes."""
    if head[:4] in (b'FREA', b'FREE'):
        return KIND_FREA
    if head[:2] in ZLIB_MAGICS:
        return KIND_ZLIB
    if head[:4] == b'RIFF':
        return KIND_RIFF
    return KIND_RAW


def aes256_ecb_decrypt(key, ct):
    if len(key) != 32 or len(ct) % 16 != 0:
        return None
    c = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    return c.decryptor().update(ct) + c.decryptor().finalize()


def decrypt_frea(file_bytes, sha1_hex, rsa):
    """RSA-recover + AES-256-ECB decrypt a FREA file. Returns a dict or None."""
    if file_bytes[:4] not in (b'FREA', b'FREE'):
        return None
    key_size = 256
    if len(file_bytes) < 6 + key_size + 16:
        return None
    if (len(file_bytes) - 6 - key_size) % 16 != 0:
        return None
    key_block = file_bytes[6:6 + key_size]
    ct = file_bytes[6 + key_size:]
    c_int = int.from_bytes(key_block, 'big')
    if c_int >= rsa.n:
        return None
    recovered = pow(c_int, rsa.e, rsa.n).to_bytes(key_size, 'big')
    key_data = recovered[12:]  # strip 12-byte PKCS#1 v1.5 padding
    sha1_bytes = sha1_hex.lower().encode('ascii')[:32]
    aes_key = bytes(a ^ b for a, b in zip(key_data[4:36], sha1_bytes))
    pt = aes256_ecb_decrypt(aes_key, ct)
    if pt is None:
        return None
    return {
        'magic': file_bytes[:4],
        'recovered': recovered,
        'aes_key': aes_key,
        'envelope_size_hint': key_data[0] | (key_data[1] << 8) | (key_data[2] << 16),
        'plaintext': pt,
    }


def find_zlib(buf, search_limit=None):
    """Locate the first *valid* zlib stream by scanning the whole buffer.

    Returns ``(offset, decompressed_bytes, compressed_len)`` or ``(-1, None, 0)``.
    Validation = the stream actually inflates; this rejects the false ``78 01``
    matches that appear inside length fields and inside ascii like ``texture``.
    """
    n = len(buf)
    end = n - 1 if search_limit is None else min(n - 1, search_limit)
    i = 0
    while i < end:
        if buf[i] == 0x78 and buf[i + 1] in (0x9c, 0xda, 0x01, 0x5e):
            try:
                d = zlib.decompressobj()
                out = d.decompress(buf[i:])
                out += d.flush()
                if len(out) > 0:
                    consumed = (n - i) - len(d.unused_data)
                    if consumed > 8:
                        return i, out, consumed
            except Exception:
                pass
        i += 1
    return -1, None, 0


# ----------------------------------------------------------------------------
# COBRA package name table (FREA only)
# ----------------------------------------------------------------------------

_NAME_CHARS = set(
    b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:.-/ '
)
_TYPE_TAGS = {'STATIC', 'DYNAMIC', 'SKINNED', 'SKELETAL'}


def _is_table_entry(b):
    return 2 <= len(b) <= 160 and all(c in _NAME_CHARS for c in b)


def _has_alpha(s):
    return any(('a' <= c <= 'z') or ('A' <= c <= 'Z') for c in s)


def parse_name_table(buf, limit):
    """Parse the leading null-terminated string table of a decrypted package.

    The table runs from offset 0 until the first non-name byte (the binary
    record table that follows). Entries that carry a ``:`` namespace, are pure
    numbers, or are bare type tokens (``STATIC``) are classified as *tags*; the
    rest are asset *names*.

    Returns ``(type_tag, tags, names, table_end_offset)``.
    """
    tags, names = [], []
    pos = 0
    stop = limit if limit and limit > 0 else len(buf)
    while pos < stop:
        end = buf.find(b'\x00', pos)
        if end < 0 or end > stop:
            break
        s = buf[pos:end]
        if not _is_table_entry(s):
            break
        txt = s.decode('ascii')
        if (':' in txt) or (txt in _TYPE_TAGS) or (not _has_alpha(txt)):
            tags.append(txt)
        else:
            names.append(txt)
        pos = end + 1
    type_tag = tags[0] if tags else None
    return type_tag, tags, names, pos


def build_tree(names):
    """Build a nested ``dict`` folder tree from dotted asset names.

    ``mat`` / ``mat.paomap`` / ``mat.paomap_lod0`` ->
        {'mat': {'paomap': {'lod0'... }}}  (split on '.').
    """
    tree = {}
    for name in names:
        node = tree
        for part in name.split('.'):
            node = node.setdefault(part, {})
    return tree


# ----------------------------------------------------------------------------
# Classification (Elite Dangerous / COBRA aware)
# ----------------------------------------------------------------------------

# Payload magic bytes (checked against the decompressed COBRA payload / raw data)
_MAGIC_TYPES = [
    (b'DDS ', 'Texture', 'DDS Texture'),
    (b'FSB5', 'Audio', 'FMOD Sound Bank (FSB5)'),
    (b'\x89PNG', 'Image', 'PNG Image'),
    (b'OggS', 'Audio', 'Ogg Vorbis Audio'),
    (b'RIFF', 'Audio', 'RIFF / WAV Audio'),
    (b'\xabKTX 11\xbb\r\n\x1a\n', 'Texture', 'KTX 1.1 Texture'),
    (b'\xabKTX 20\xbb\r\n\x1a\n', 'Texture', 'KTX 2.0 Texture'),
    (b'glTF', 'Model', 'glTF Binary'),
    (b'BKHD', 'Audio', 'Wwise Bank (BKHD)'),
    (b'<?xml', 'Text', 'XML Document'),
    (b'DXBC', 'Shader', 'DirectX Bytecode Shader'),
]

# COBRA package type-tag suffix (the part after the last ':' is always intact,
# even when the tag's prefix is truncated in the buffer e.g. 'ect:GreebleDef').
_TYPE_SUFFIX_MAP = {
    'texturestream': ('Texture', 'Texture Stream'),
    'tex': ('Texture', 'Texture'),
    'texture': ('Texture', 'Texture'),
    'model2stream': ('Mesh', 'Model Stream'),
    'modelstream': ('Mesh', 'Model Stream'),
    'modelset2': ('Mesh', 'Model Set'),
    'ms2': ('Mesh', 'Model Set'),
    'model2': ('Mesh', 'Model'),
    'mdl2': ('Mesh', 'Model'),
    'model': ('Mesh', 'Model'),
    'csm': ('StateMachine', 'Code State Machine'),
    'statemachine': ('StateMachine', 'State Machine'),
    'kinematic': ('Rig', 'Kinematic Rig'),
    'krig': ('Rig', 'Kinematic Rig'),
    'greeble': ('Decoration', 'Greeble Definition'),
    'greebledef': ('Decoration', 'Greeble Definition'),
    'decal': ('Decal', 'Decal'),
    'paintjob': ('Material', 'Paint Job'),
    'humanoidpaintjob': ('Material', 'Humanoid Paint Job'),
    'fgm': ('Material', 'Frontier Game Material'),
    'mat': ('Material', 'Material'),
    'matlib': ('Material', 'Material Library'),
    'fontlib': ('UI', 'Font Library'),
    'font': ('UI', 'Font'),
    'uitexture': ('UI', 'UI Texture'),
}

# Regex patterns over an asset / file name (lower-cased).
_NAME_PATTERNS = [
    (r'\.paomap', 'Material', 'PAO Map'),
    (r'\.pbasecolour|_basecolour|_albedo|_diff', 'Texture', 'Base Colour Map'),
    (r'\.pnormal|_norm(al)?(\b|_)|_nrm', 'Texture', 'Normal Map'),
    (r'\.pmetal|_metal', 'Texture', 'Metalness Map'),
    (r'\.proughness|_rough', 'Texture', 'Roughness Map'),
    (r'\.pemissive|_emis|_emit', 'Texture', 'Emissive Map'),
    (r'\.pblendmask|_blendmask|_mask', 'Texture', 'Mask Map'),
    (r'\.plookup', 'Texture', 'Lookup Map'),
    (r'_ao(\b|_)|_occl', 'Texture', 'Ambient Occlusion Map'),
    (r'_alpha|_opac', 'Texture', 'Alpha Map'),
    (r'_spec', 'Texture', 'Specular Map'),
    (r'_lod\d+', 'Mesh', 'LOD Variant'),
    (r'_icon|_thumb', 'UI', 'Icon / Thumbnail'),
    (r'^uti\d+_b_hands', 'Suit', 'Suit Gloves'),
    (r'^uti\d+_b_body', 'Suit', 'Suit Body'),
    (r'^uti\d+_b_legs', 'Suit', 'Suit Legs'),
    (r'^uti\d+_b_(helm|head)', 'Suit', 'Suit Helmet'),
    (r'^uti\d+_', 'Suit', 'On-foot Item'),
    (r'^tac\d+', 'Suit', 'Tactical Suit Part'),
    (r'^pilot\d*', 'Character', 'Pilot Asset'),
    (r'^ship_|_ship\b', 'Ship', 'Ship Asset'),
    (r'cobra|anaconda|sidewinder|python|federation_corvette|lakon', 'Ship', 'Ship Asset'),
    (r'^srv_|buggy', 'Vehicle', 'SRV / Buggy'),
    (r'^pln_|planet', 'World', 'Planet Asset'),
    (r'^stn_|station|settlement|hangar', 'World', 'Station / Settlement'),
    (r'voxgen|_vox|_voice|_vo_|greetings', 'Audio', 'Voice / Dialogue'),
    (r'^snd_|_sfx|_audio', 'Audio', 'Sound Effect'),
    (r'^mus_|_music', 'Audio', 'Music'),
    (r'_amb(\b|_)', 'Audio', 'Ambient Audio'),
    (r'decal|nameplate|vinyl', 'Decal', 'Decal / Livery'),
    (r'_anim|skeleton|_rig\b', 'Animation', 'Animation / Rig'),
    (r'_font|^fnt_', 'UI', 'Font'),
    (r'_shader|_shdr|^shd_', 'Shader', 'Shader'),
    (r'_vfx|_fx_|_particle|_effect', 'VFX', 'Visual Effect'),
]


def classify(type_tag, names, payload_head, kind):
    """Return ``(category, type_desc)`` for an asset."""
    # 1) Hard magic on the payload.
    if payload_head:
        for magic, cat, desc in _MAGIC_TYPES:
            if payload_head.startswith(magic):
                return cat, desc
    # 2) COBRA package type-tag suffix (the reliable, untruncated part).
    if type_tag:
        suffix = type_tag.split(':')[-1].strip().lower()
        if suffix in _TYPE_SUFFIX_MAP:
            return _TYPE_SUFFIX_MAP[suffix]
    # 3) Name-pattern heuristics.
    for name in names or ():
        ln = name.lower()
        for pattern, cat, desc in _NAME_PATTERNS:
            if re.search(pattern, ln):
                return cat, desc
    # 4) Fall back on kind.
    if kind == KIND_RIFF:
        return 'Audio', 'WAV Audio'
    if kind == KIND_ZLIB:
        return 'Resource', 'COBRA Resource Blob'
    return 'FREA', 'COBRA Package'


def classify_resource(name, kind=KIND_FREA):
    """Classify a single contained resource by its (dotted) name, name-first.

    Unlike :func:`classify`, this ignores the package type tag so an individual
    entry like ``mat.pnormaltexture_lod0`` is labelled "Normal Map" rather than
    inheriting the package's "Texture Stream".
    """
    leaf = name.split('.')[-1].lower()
    for pattern, cat, desc in _NAME_PATTERNS:
        if re.search(pattern, name.lower()) or re.search(pattern, leaf):
            return cat, desc
    return classify(None, [name], b'', kind)


# ----------------------------------------------------------------------------
# High-level Asset object
# ----------------------------------------------------------------------------

@dataclass
class Asset:
    sha1: str
    subdir: str = ''
    file_size: int = 0
    kind: str = KIND_RAW
    ok: bool = False
    error: str = None

    # decoded data
    decrypted: bytes = None       # FREA only: AES plaintext (envelope+zlib)
    payload: bytes = None         # decompressed COBRA data / RIFF bytes / raw
    zlib_off: int = -1
    aes_key: bytes = None

    # package metadata (FREA with a name table)
    type_tag: str = None
    tags: list = field(default_factory=list)
    names: list = field(default_factory=list)
    tree: dict = field(default_factory=dict)

    category: str = ''
    type_desc: str = ''

    @property
    def payload_size(self):
        return len(self.payload) if self.payload else 0

    @property
    def primary_name(self):
        """Best display name: the shortest root of the name tree, else sha1."""
        if self.names:
            roots = sorted({n.split('.')[0] for n in self.names}, key=len)
            return roots[0]
        return self.sha1

    @property
    def is_named(self):
        return bool(self.names)


def open_asset(file_bytes, sha1, rsa, subdir=''):
    """Decode any Win64 asset file into an :class:`Asset`. Never raises."""
    a = Asset(sha1=sha1, subdir=subdir, file_size=len(file_bytes))
    head = file_bytes[:8]
    a.kind = classify_kind(head)
    try:
        if a.kind == KIND_FREA:
            res = decrypt_frea(file_bytes, sha1, rsa)
            if res is None:
                a.error = "decrypt failed (bad alignment / RSA range)"
                return a
            a.decrypted = res['plaintext']
            a.aes_key = res['aes_key']
            off, payload, _ = find_zlib(a.decrypted)
            a.zlib_off = off
            if payload is not None:
                a.payload = payload
            # name table spans [0, zlib_off)
            a.type_tag, a.tags, a.names, _ = parse_name_table(
                a.decrypted, off if off > 0 else len(a.decrypted))
            a.tree = build_tree(a.names)
            a.ok = a.payload is not None

        elif a.kind == KIND_ZLIB:
            try:
                d = zlib.decompressobj()
                out = d.decompress(file_bytes)
                out += d.flush()
                a.payload = out
                a.zlib_off = 0
                a.ok = True
            except Exception as ex:
                a.error = f"zlib decompress failed: {ex}"

        elif a.kind == KIND_RIFF:
            a.payload = file_bytes
            a.ok = True

        else:  # KIND_RAW
            a.payload = file_bytes
            a.ok = True
    except Exception as ex:  # never let a single file kill a batch
        a.error = f"{type(ex).__name__}: {ex}"
        return a

    head_p = a.payload[:16] if a.payload else b''
    a.category, a.type_desc = classify(a.type_tag, a.names, head_p, a.kind)
    return a


# ----------------------------------------------------------------------------
# Misc helpers
# ----------------------------------------------------------------------------

def safe_filename(name, maxlen=96):
    s = re.sub(r'[\\/:*?"<>|]+', '_', name).strip('. ')
    return s[:maxlen] or 'unnamed'


def fmt_size(n):
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def extract_strings(data, min_len=4, limit=None):
    chunk = data[:limit] if limit else data
    return [m.group().decode('ascii', 'replace')
            for m in re.finditer(rb'[\x20-\x7e]{%d,}' % min_len, chunk)]


def hexdump(data, max_bytes=4096, base=0):
    lines = []
    for i in range(0, min(len(data), max_bytes), 16):
        chunk = data[i:i + 16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{base + i:08x}  {hex_part:<48}  {ascii_part}")
    return '\n'.join(lines)


def iter_subdirs(win64_dir):
    for sub in sorted(os.listdir(win64_dir)):
        sd = Path(win64_dir) / sub
        if sd.is_dir() and len(sub) == 2 and all(c in '0123456789abcdef' for c in sub):
            yield sub, sd


def iter_asset_files(win64_dir):
    """Yield (subdir, sha1, full_path) for every 40-hex-char asset file."""
    for sub, sd in iter_subdirs(win64_dir):
        try:
            entries = sorted(os.listdir(sd))
        except OSError:
            continue
        for fn in entries:
            if len(fn) == 40 and all(c in '0123456789abcdef' for c in fn):
                yield sub, fn, sd / fn
