"""
FREA Asset Explorer
====================
7-zip-style GUI browser for Elite Dangerous Odyssey ``Win64`` asset files.

All decoding lives in ``frea_core`` (shared with the CLI ``frea_extract.py``),
so the explorer understands every file kind in the data set - not just FREA:

    FREA  encrypted COBRA package (has a name table -> proper names & folders)
    zlib  raw zlib resource blob (hash-named; no embedded names)
    RIFF  WAV audio
    raw   anything else (passed through)

Tree layout (the file itself is the "root folder"):

    Win64
      00 .. 0f
        <package>            <- level 1: one Win64 file = one archive/folder
          <asset>            <- level 2: a contained resource
            <sub-asset>      <- level 3+: dotted names become nested folders
                             (e.g. mat -> paomap -> lod0)

Right pane: a sortable contents list + tabbed details (Info / Hex / Strings /
Preview). Inner resources are named from the package's name table and classified
with an Elite-Dangerous / COBRA aware type lookup.
"""

import os
import re
import sys
import zlib
import tempfile
import threading
import subprocess
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

import frea_core as fc


GAME_DIR_DEFAULTS = [
    r'F:\SteamLibrary\steamapps\common\Elite Dangerous\Products\elite-dangerous-odyssey-64',
    r'C:\Program Files (x86)\Steam\steamapps\common\Elite Dangerous\Products\elite-dangerous-odyssey-64',
    r'D:\SteamLibrary\steamapps\common\Elite Dangerous\Products\elite-dangerous-odyssey-64',
]

EXT_BY_KIND = {fc.KIND_FREA: '.cobra', fc.KIND_ZLIB: '.cobra',
               fc.KIND_RIFF: '.wav', fc.KIND_RAW: '.bin'}


class FreaExplorer:
    def __init__(self, root):
        self.root = root
        self.root.title("FREA Asset Explorer - Elite Dangerous Odyssey")
        self.root.geometry("1680x920")

        self.game_dir = None
        self.win64_dir = None
        self.binary_path = None
        self.rsa = None
        # meta[sha1] = lightweight metadata dict (no payload kept)
        self.meta = {}
        self.scan_thread = None
        self.scan_stop = threading.Event()

        # last decoded asset for the details pane (payload kept only here)
        self._cur = None  # frea_core.Asset

        self._build_ui()

        for d in GAME_DIR_DEFAULTS:
            if (Path(d) / 'Win64').is_dir():
                if self.load_archive(d):
                    self.populate_tree()
                break

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        fm = tk.Menu(menubar, tearoff=0)
        fm.add_command(label="Open Game Directory...", command=self.open_game_dir)
        fm.add_separator()
        fm.add_command(label="Extract Selected (payload)...",
                       command=lambda: self.extract_selected('payload'))
        fm.add_command(label="Extract Selected (decrypted FREA)...",
                       command=lambda: self.extract_selected('decrypt'))
        fm.add_command(label="Extract Selected (raw file)...",
                       command=lambda: self.extract_selected('raw'))
        fm.add_separator()
        fm.add_command(label="Extract Entire Archive...", command=self.extract_all)
        fm.add_separator()
        fm.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=fm)

        vm = tk.Menu(menubar, tearoff=0)
        vm.add_command(label="Scan Names in Current Folder", command=self.scan_current_folder)
        vm.add_command(label="Stop Scan", command=lambda: self.scan_stop.set())
        vm.add_command(label="Refresh", command=self.refresh_current)
        menubar.add_cascade(label="View", menu=vm)

        hm = tk.Menu(menubar, tearoff=0)
        hm.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=hm)

        tb = ttk.Frame(self.root, padding=4)
        tb.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(tb, text="Open", command=self.open_game_dir).pack(side=tk.LEFT, padx=2)
        ttk.Separator(tb, orient='vertical').pack(side=tk.LEFT, fill=tk.Y, padx=6)
        ttk.Button(tb, text="Extract", command=lambda: self.extract_selected('payload')).pack(side=tk.LEFT, padx=2)
        ttk.Button(tb, text="Scan Names", command=self.scan_current_folder).pack(side=tk.LEFT, padx=2)
        ttk.Separator(tb, orient='vertical').pack(side=tk.LEFT, fill=tk.Y, padx=6)
        ttk.Label(tb, text="Filter:").pack(side=tk.LEFT, padx=4)
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add('write', lambda *a: self.apply_filter())
        ttk.Entry(tb, textvariable=self.filter_var, width=42).pack(side=tk.LEFT, padx=2)

        addr = ttk.Frame(self.root, padding=(4, 0))
        addr.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(addr, text="Archive:").pack(side=tk.LEFT)
        self.addr_var = tk.StringVar(value="(no archive open)")
        ttk.Label(addr, textvariable=self.addr_var, foreground="#0050a0").pack(side=tk.LEFT, padx=4)

        main = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # ---- left: tree ----
        tf = ttk.Frame(main)
        ttk.Label(tf, text="Folders / Packages", font=('Segoe UI', 9, 'bold')).pack(anchor='w')
        ti = ttk.Frame(tf)
        ti.pack(fill=tk.BOTH, expand=True)
        self.tree = ttk.Treeview(ti, show='tree', selectmode='browse', height=30)
        tsb = ttk.Scrollbar(ti, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        self.tree.bind('<<TreeviewOpen>>', self.on_tree_expand)
        main.add(tf, weight=1)

        # ---- right ----
        right = ttk.PanedWindow(main, orient=tk.VERTICAL)

        lf = ttk.Frame(right)
        self.list_title = tk.StringVar(value="Contents")
        ttk.Label(lf, textvariable=self.list_title, font=('Segoe UI', 9, 'bold')).pack(anchor='w')
        li = ttk.Frame(lf)
        li.pack(fill=tk.BOTH, expand=True)
        cols = ('name', 'kind', 'category', 'type', 'res', 'size', 'payload', 'sha1')
        headings = {
            'name':     ('Name',         300, 'w'),
            'kind':     ('Kind',          60, 'w'),
            'category': ('Category',     110, 'w'),
            'type':     ('Type',         200, 'w'),
            'res':      ('#Res',          50, 'e'),
            'size':     ('File Size',     90, 'e'),
            'payload':  ('Payload',       90, 'e'),
            'sha1':     ('SHA1',         240, 'w'),
        }
        self.flist = ttk.Treeview(li, columns=cols, show='headings', selectmode='extended', height=18)
        self._sort_rev = {}
        for c in cols:
            text, w, anchor = headings[c]
            self.flist.heading(c, text=text, command=lambda cc=c: self.sort_by(cc))
            self.flist.column(c, width=w, anchor=anchor)
        vsb = ttk.Scrollbar(li, command=self.flist.yview)
        hsb = ttk.Scrollbar(li, orient='horizontal', command=self.flist.xview)
        self.flist.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.flist.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        li.rowconfigure(0, weight=1)
        li.columnconfigure(0, weight=1)
        self.flist.bind('<<TreeviewSelect>>', self.on_flist_select)
        self.flist.bind('<Double-1>', lambda e: self.open_in_os())
        self.flist.bind('<Button-3>', self.on_flist_rclick)
        right.add(lf, weight=3)

        self.ctx = tk.Menu(self.root, tearoff=0)
        self.ctx.add_command(label="Open with OS", command=self.open_in_os)
        self.ctx.add_separator()
        self.ctx.add_command(label="Extract payload...", command=lambda: self.extract_selected('payload'))
        self.ctx.add_command(label="Extract decrypted FREA...", command=lambda: self.extract_selected('decrypt'))
        self.ctx.add_command(label="Extract raw file...", command=lambda: self.extract_selected('raw'))
        self.ctx.add_separator()
        self.ctx.add_command(label="Copy SHA1", command=self.copy_sha1)
        self.ctx.add_command(label="Copy Name", command=self.copy_name)

        df = ttk.Frame(right)
        self.nb = ttk.Notebook(df)
        self.nb.pack(fill=tk.BOTH, expand=True)

        inf = ttk.Frame(self.nb)
        self.info_text = scrolledtext.ScrolledText(inf, font=('Consolas', 9), wrap=tk.NONE,
                                                    height=12, state='disabled')
        self.info_text.pack(fill=tk.BOTH, expand=True)
        self.nb.add(inf, text='Info')

        hxf = ttk.Frame(self.nb)
        self.hex_choice = tk.StringVar(value='payload')
        cb = ttk.Frame(hxf)
        cb.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(cb, text="View:").pack(side=tk.LEFT, padx=2)
        for v, lbl in [('raw', 'Raw file'), ('decrypted', 'Decrypted'), ('payload', 'Payload')]:
            ttk.Radiobutton(cb, text=lbl, variable=self.hex_choice, value=v,
                            command=self.refresh_hex).pack(side=tk.LEFT, padx=2)
        self.hex_text = scrolledtext.ScrolledText(hxf, font=('Consolas', 9), wrap=tk.NONE,
                                                   height=12, state='disabled')
        self.hex_text.pack(fill=tk.BOTH, expand=True)
        self.nb.add(hxf, text='Hex')

        sf = ttk.Frame(self.nb)
        self.str_text = scrolledtext.ScrolledText(sf, font=('Consolas', 9), wrap=tk.WORD,
                                                   height=12, state='disabled')
        self.str_text.pack(fill=tk.BOTH, expand=True)
        self.nb.add(sf, text='Strings')

        pf = ttk.Frame(self.nb)
        self.prev_text = scrolledtext.ScrolledText(pf, font=('Consolas', 9), wrap=tk.WORD,
                                                    height=12, state='disabled')
        self.prev_text.pack(fill=tk.BOTH, expand=True)
        self.nb.add(pf, text='Preview')

        right.add(df, weight=2)
        main.add(right, weight=5)

        sb = ttk.Frame(self.root)
        sb.pack(side=tk.BOTTOM, fill=tk.X)
        self.status = tk.StringVar(value="Ready")
        ttk.Label(sb, textvariable=self.status, anchor='w', relief=tk.SUNKEN).pack(
            side=tk.LEFT, fill=tk.X, expand=True)
        self.pbar_var = tk.IntVar(value=0)
        self.pbar = ttk.Progressbar(sb, variable=self.pbar_var, length=240, mode='determinate')
        self.pbar.pack(side=tk.RIGHT, padx=4)

    def _set(self, widget, text):
        widget.config(state='normal')
        widget.delete('1.0', tk.END)
        widget.insert('1.0', text)
        widget.config(state='disabled')

    def show_about(self):
        messagebox.showinfo(
            "About",
            "FREA Asset Explorer\n\n"
            "Browses Elite Dangerous Odyssey Win64 asset files.\n\n"
            "Handles encrypted FREA packages (RSA-2048 + AES-256-ECB), raw zlib\n"
            "resource blobs, and RIFF/WAV audio. FREA packages carry a name table\n"
            "whose dotted names form the folder tree shown under each package.")

    # ------------------------------------------------------ archive loading
    def open_game_dir(self):
        d = filedialog.askdirectory(title="Select 'elite-dangerous-odyssey-64' folder")
        if d and self.load_archive(d):
            self.populate_tree()

    def load_archive(self, game_dir):
        self.game_dir = Path(game_dir)
        self.win64_dir = self.game_dir / 'Win64'
        self.binary_path = self.game_dir / 'EliteDangerous64.exe'
        if not self.win64_dir.exists():
            messagebox.showerror("Error", f"Win64/ missing in:\n{game_dir}")
            return False
        # RSA key is baked in; only read the binary if it's present (to catch a key change).
        if self.binary_path.exists():
            try:
                self.rsa = fc.load_rsa_key(self.binary_path)
            except Exception:
                self.rsa = fc.default_rsa_key()
        else:
            self.rsa = fc.default_rsa_key()
        self.meta.clear()
        self.addr_var.set(str(self.game_dir))
        self.status.set(f"Opened {self.game_dir.name}. RSA {self.rsa.n.bit_length()}-bit, E={self.rsa.e}")
        return True

    # --------------------------------------------------- decode + meta cache
    def _read(self, subdir, sha1):
        return (self.win64_dir / subdir / sha1).read_bytes()

    def decode(self, subdir, sha1):
        """Decode a file into an Asset (payload included). Caches lightweight meta."""
        data = self._read(subdir, sha1)
        asset = fc.open_asset(data, sha1, self.rsa, subdir)
        self.meta[sha1] = {
            'kind': asset.kind, 'category': asset.category, 'type_desc': asset.type_desc,
            'primary': asset.primary_name, 'is_named': asset.is_named,
            'num_names': len(asset.names), 'names': asset.names, 'tree': asset.tree,
            'payload_size': asset.payload_size, 'file_size': asset.file_size,
            'type_tag': asset.type_tag, 'ok': asset.ok, 'error': asset.error,
        }
        return asset

    def _file_label(self, sha1, m):
        """Tree label for a level-1 package node."""
        kind = m.get('kind', '?')
        type_desc = m.get('type_desc', '')
        if m.get('is_named'):
            return f"{m['primary']}  [{sha1[:8]}…]  ·  {type_desc}"
        return f"{sha1[:16]}…  ·  {type_desc} ({kind})"

    # ------------------------------------------------------ tree population
    def populate_tree(self):
        for it in self.tree.get_children():
            self.tree.delete(it)
        if not self.win64_dir:
            return
        self.tree.insert('', 'end', text='Win64', open=True, iid='root')
        total = 0
        for sub, sd in fc.iter_subdirs(self.win64_dir):
            try:
                cnt = sum(1 for f in sd.iterdir() if len(f.name) == 40)
            except OSError:
                cnt = 0
            total += cnt
            node = f'sub:{sub}'
            self.tree.insert('root', 'end', text=f"{sub}  ({cnt:,} files)", iid=node)
            self.tree.insert(node, 'end', text='loading...', iid=f'_ph:{node}')
        self.status.set(f"Archive ready. {total:,} asset files. Expand a folder to browse.")

    def _populate_subdir(self, sub_node, subdir):
        sd = self.win64_dir / subdir
        try:
            files = sorted(f.name for f in sd.iterdir() if len(f.name) == 40)
        except OSError:
            return
        for sha1 in files:
            m = self.meta.get(sha1)
            label = self._file_label(sha1, m) if m else f"{sha1[:16]}…"
            node = f'file:{subdir}:{sha1}'
            self.tree.insert(sub_node, 'end', text=label, iid=node)
            # placeholder => expandable; resolved on first expand
            self.tree.insert(node, 'end', text='...', iid=f'_ph:{node}')

    def _insert_tree_nodes(self, parent_iid, subdir, sha1, subtree, prefix):
        for key in sorted(subtree):
            path = f"{prefix}.{key}" if prefix else key
            niid = f'node:{subdir}:{sha1}:{path}'
            self.tree.insert(parent_iid, 'end', text=key, iid=niid)
            if subtree[key]:
                self._insert_tree_nodes(niid, subdir, sha1, subtree[key], path)

    def _populate_file(self, file_node, subdir, sha1):
        try:
            asset = self.decode(subdir, sha1)
        except Exception as ex:
            self.tree.insert(file_node, 'end', text=f"<error: {ex}>", iid=f'_err:{file_node}')
            return
        m = self.meta[sha1]
        self.tree.item(file_node, text=self._file_label(sha1, m))
        if asset.tree:
            self._insert_tree_nodes(file_node, subdir, sha1, asset.tree, '')
        # named-but-flat or anonymous: no children (it is a single resource = the file itself)

    def on_tree_expand(self, _ev):
        node = self.tree.focus()
        ph = f'_ph:{node}'
        if not self.tree.exists(ph):
            return
        self.tree.delete(ph)
        if node.startswith('sub:'):
            self._populate_subdir(node, node[4:])
        elif node.startswith('file:'):
            _, subdir, sha1 = node.split(':', 2)
            self._populate_file(file_node=node, subdir=subdir, sha1=sha1)

    def on_tree_select(self, _ev):
        sel = self.tree.selection()
        if not sel:
            return
        node = sel[0]
        if node == 'root':
            self.list_title.set("Contents — Win64 (folders)")
            self._list_subdirs()
        elif node.startswith('sub:'):
            sub = node[4:]
            self.list_title.set(f"Contents — {sub}/")
            self._list_files(sub)
        elif node.startswith('file:'):
            _, sub, sha1 = node.split(':', 2)
            self.list_title.set(f"Contents — {sub}/{sha1[:12]}…")
            self.show_details(sub, sha1, None)
            self._list_resources(sub, sha1, None)
        elif node.startswith('node:'):
            _, sub, sha1, path = node.split(':', 3)
            self.list_title.set(f"Contents — {path}")
            self.show_details(sub, sha1, path)
            self._list_resources(sub, sha1, path)

    # ------------------------------------------------------ file list
    def _clear_list(self):
        for it in self.flist.get_children():
            self.flist.delete(it)

    def _list_subdirs(self):
        self._clear_list()
        for sub, sd in fc.iter_subdirs(self.win64_dir):
            try:
                cnt = sum(1 for f in sd.iterdir() if len(f.name) == 40)
            except OSError:
                cnt = 0
            self.flist.insert('', 'end', iid=f'L-sub:{sub}',
                              values=(f"{sub}/", 'dir', 'Folder', '', f"{cnt:,}", '', '', ''))

    def _list_files(self, subdir):
        self._clear_list()
        sd = self.win64_dir / subdir
        try:
            files = sorted(f.name for f in sd.iterdir() if len(f.name) == 40)
        except OSError:
            return
        flt = self.filter_var.get().lower().strip()
        for sha1 in files:
            m = self.meta.get(sha1, {})
            name = m.get('primary', '') if m.get('is_named') else (m.get('primary', '') or '')
            disp_name = name if (m.get('is_named')) else f"{sha1[:16]}…"
            type_desc = m.get('type_desc', '')
            cat = m.get('category', '')
            kind = m.get('kind', '')
            try:
                fsz = (sd / sha1).stat().st_size
            except OSError:
                continue
            hay = f"{sha1} {name} {type_desc} {cat}".lower()
            if flt and flt not in hay:
                continue
            self.flist.insert('', 'end', iid=f'L-file:{subdir}:{sha1}', values=(
                disp_name, kind, cat, type_desc,
                m.get('num_names', '') or '',
                fc.fmt_size(fsz),
                fc.fmt_size(m['payload_size']) if m.get('payload_size') else '',
                sha1,
            ))

    def _list_resources(self, subdir, sha1, path):
        """List the contained resources of a package (or children of a folder node)."""
        self._clear_list()
        m = self.meta.get(sha1)
        if not m:
            try:
                self.decode(subdir, sha1)
                m = self.meta[sha1]
            except Exception:
                return
        names = m.get('names', [])
        if not names:
            # single-resource file: show the file itself as the one entry
            self.flist.insert('', 'end', iid=f'L-file:{subdir}:{sha1}', values=(
                m.get('primary', sha1), m.get('kind', ''), m.get('category', ''),
                m.get('type_desc', ''), '', '', fc.fmt_size(m.get('payload_size', 0)), sha1))
            return
        # filter to names under `path` (or all if path is the package root)
        for name in names:
            if path and not (name == path or name.startswith(path + '.')):
                continue
            cat, desc = fc.classify_resource(name, m.get('kind'))
            iid = f'L-res:{subdir}:{sha1}:{name}'
            self.flist.insert('', 'end', iid=iid, values=(
                name, m.get('kind', ''), cat, desc, '', '', '', sha1))

    def apply_filter(self):
        sel = self.tree.selection()
        if sel and sel[0].startswith('sub:'):
            self._list_files(sel[0][4:])

    def sort_by(self, col):
        items = [(self.flist.set(it, col), it) for it in self.flist.get_children('')]
        rev = self._sort_rev.get(col, False)

        def keyf(x):
            v = x[0]
            for suf, mul in ((' B', 1), (' KB', 1024), (' MB', 1024 * 1024)):
                if v.endswith(suf):
                    try:
                        return float(v[:-len(suf)]) * mul
                    except ValueError:
                        pass
            try:
                return float(v.replace(',', ''))
            except ValueError:
                return v.lower()

        items.sort(key=keyf, reverse=rev)
        for i, (_, it) in enumerate(items):
            self.flist.move(it, '', i)
        self._sort_rev[col] = not rev

    def refresh_current(self):
        if self.tree.selection():
            self.on_tree_select(None)

    # ------------------------------------------------------ details
    def on_flist_select(self, _ev):
        sel = self.flist.selection()
        if not sel:
            return
        iid = sel[0]
        if iid.startswith('L-sub:'):
            tn = f'sub:{iid.split(":",1)[1]}'
            if self.tree.exists(tn):
                self.tree.selection_set(tn)
                self.tree.see(tn)
        elif iid.startswith('L-file:'):
            _, sub, sha1 = iid.split(':', 2)
            self.show_details(sub, sha1, None)
        elif iid.startswith('L-res:'):
            _, sub, sha1, name = iid.split(':', 3)
            self.show_details(sub, sha1, name)

    def show_details(self, subdir, sha1, sel_path):
        try:
            asset = self.decode(subdir, sha1)
        except Exception as ex:
            self._set(self.info_text, f"Error: {ex}")
            self._cur = None
            return
        self._cur = asset
        fp = self.win64_dir / subdir / sha1
        info = [
            "=== File ===",
            f"  Path:    {fp}",
            f"  SHA1:    {sha1}",
            f"  Size:    {asset.file_size:,} bytes ({fc.fmt_size(asset.file_size)})",
            f"  Kind:    {asset.kind}",
            f"  Status:  {'OK' if asset.ok else 'ERROR: ' + (asset.error or '?')}",
            "",
            "=== Classification ===",
            f"  Category:    {asset.category}",
            f"  Type:        {asset.type_desc}",
            f"  Type tag:    {asset.type_tag}",
            f"  Resources:   {len(asset.names)}",
        ]
        if asset.kind == fc.KIND_FREA:
            info += [
                "",
                "=== FREA decrypt ===",
                f"  AES key:        {asset.aes_key.hex() if asset.aes_key else '(n/a)'}",
                f"  Decrypted size: {len(asset.decrypted):,} bytes" if asset.decrypted else "  (no plaintext)",
                f"  zlib offset:    {('0x%x' % asset.zlib_off) if asset.zlib_off >= 0 else 'not found'}",
            ]
        info += [
            "",
            "=== Payload ===",
            f"  Decompressed: {asset.payload_size:,} bytes ({fc.fmt_size(asset.payload_size)})",
            f"  Head:         {asset.payload[:16].hex() if asset.payload else '(none)'}",
        ]
        if asset.names:
            info += ["", "=== Contained resources (folder tree) ==="]
            info += ['  ' + ln for ln in self._render_tree(asset.tree)][:400]
        if sel_path:
            cat, desc = fc.classify_resource(sel_path, asset.kind)
            info += ["", "=== Selected resource ===", f"  Name:     {sel_path}",
                     f"  Category: {cat}", f"  Type:     {desc}"]
        self._set(self.info_text, '\n'.join(info))
        self.refresh_hex()
        self._refresh_strings()
        self._refresh_preview()

    @staticmethod
    def _render_tree(tree, indent=0):
        out = []
        for k in sorted(tree):
            out.append('  ' * indent + '- ' + k)
            out.extend(FreaExplorer._render_tree(tree[k], indent + 1))
        return out

    def refresh_hex(self):
        if not self._cur:
            self._set(self.hex_text, "(no data)")
            return
        choice = self.hex_choice.get()
        data = None
        if choice == 'raw':
            try:
                data = self._read(self._cur.subdir, self._cur.sha1)
            except Exception:
                data = None
        elif choice == 'decrypted':
            data = self._cur.decrypted
        else:
            data = self._cur.payload
        self._set(self.hex_text, fc.hexdump(data, 8192) if data else f"(no {choice} data)")

    def _refresh_strings(self):
        if not self._cur or not self._cur.payload:
            self._set(self.str_text, "(no data)")
            return
        strs = fc.extract_strings(self._cur.payload, 4, limit=131072)
        self._set(self.str_text, '\n'.join(strs) if strs else "(no printable strings)")

    def _refresh_preview(self):
        data = self._cur.payload if self._cur else None
        if not data:
            self._set(self.prev_text, "(no preview)")
            return
        for enc in ('utf-8', 'utf-16-le', 'latin-1'):
            try:
                txt = data[:65536].decode(enc)
                ok = sum(1 for c in txt[:1024] if c.isprintable() or c in '\n\r\t')
                if ok / max(1, min(len(txt), 1024)) > 0.85:
                    self._set(self.prev_text, txt)
                    return
            except UnicodeDecodeError:
                continue
        self._set(self.prev_text, fc.hexdump(data, 4096))

    # ------------------------------------------------------ context menu
    def on_flist_rclick(self, event):
        iid = self.flist.identify_row(event.y)
        if iid:
            if iid not in self.flist.selection():
                self.flist.selection_set(iid)
            self.ctx.tk_popup(event.x_root, event.y_root)

    def _sha1_of(self, iid):
        if iid.startswith('L-file:'):
            return iid.split(':', 2)[2]
        if iid.startswith('L-res:'):
            return iid.split(':', 3)[2]
        return None

    def copy_sha1(self):
        sel = self.flist.selection()
        if sel and (s := self._sha1_of(sel[0])):
            self.root.clipboard_clear()
            self.root.clipboard_append(s)
            self.status.set(f"Copied SHA1: {s}")

    def copy_name(self):
        sel = self.flist.selection()
        if sel:
            v = self.flist.item(sel[0])['values']
            if v:
                self.root.clipboard_clear()
                self.root.clipboard_append(str(v[0]))
                self.status.set(f"Copied: {v[0]}")

    def open_in_os(self):
        sel = self.flist.selection()
        if not sel:
            return
        iid = sel[0]
        parts = iid.split(':')
        if parts[0] not in ('L-file', 'L-res'):
            return
        subdir, sha1 = parts[1], parts[2]
        try:
            asset = self.decode(subdir, sha1)
        except Exception as ex:
            messagebox.showerror("Error", str(ex))
            return
        if not asset.payload:
            messagebox.showwarning("No data", "Nothing to open for this file.")
            return
        tmp = Path(tempfile.gettempdir()) / 'frea_explorer'
        tmp.mkdir(parents=True, exist_ok=True)
        v = self.flist.item(iid)['values']
        name = fc.safe_filename(str(v[0]) if v else sha1, 64)
        target = tmp / f"{name}{EXT_BY_KIND.get(asset.kind, '.bin')}"
        target.write_bytes(asset.payload)
        try:
            if sys.platform == 'win32':
                os.startfile(str(target))
            elif sys.platform == 'darwin':
                subprocess.run(['open', str(target)])
            else:
                subprocess.run(['xdg-open', str(target)])
            self.status.set(f"Opened {target.name}")
        except Exception as ex:
            messagebox.showerror("Error", f"Could not open: {ex}")

    # ------------------------------------------------------ extraction
    def extract_selected(self, mode):
        sel = self.flist.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select one or more items in the list.")
            return
        out = filedialog.askdirectory(title=f"Extract {len(sel)} item(s) to...")
        if not out:
            return
        out = Path(out)
        out.mkdir(parents=True, exist_ok=True)
        seen = set()
        ok = err = 0
        for iid in sel:
            parts = iid.split(':')
            if parts[0] not in ('L-file', 'L-res'):
                continue
            subdir, sha1 = parts[1], parts[2]
            if (subdir, sha1) in seen:
                continue
            seen.add((subdir, sha1))
            try:
                self._extract_one(subdir, sha1, out, mode)
                ok += 1
            except Exception as ex:
                err += 1
                print(f"[!] {subdir}/{sha1}: {ex}")
        self.status.set(f"Extracted {ok} ({err} errors) -> {out}")
        messagebox.showinfo("Extract complete", f"Extracted: {ok}\nErrors: {err}\nOutput: {out}")

    def _extract_one(self, subdir, sha1, out, mode):
        data = self._read(subdir, sha1)
        if mode == 'raw':
            (out / f"{sha1}.frea").write_bytes(data)
            return
        asset = fc.open_asset(data, sha1, self.rsa, subdir)
        base = (f"{fc.safe_filename(asset.primary_name, 80)}__{sha1[:8]}"
                if asset.is_named else sha1)
        if mode == 'decrypt':
            if asset.decrypted is None:
                raise RuntimeError("not a FREA file / decrypt failed")
            (out / f"{base}.decrypted").write_bytes(asset.decrypted)
            return
        # payload
        if asset.payload is None:
            raise RuntimeError(asset.error or "no payload")
        (out / f"{base}{EXT_BY_KIND.get(asset.kind, '.bin')}").write_bytes(asset.payload)
        if asset.is_named:
            lines = [f"package: {asset.primary_name}", f"sha1: {sha1}",
                     f"type: {asset.type_desc} ({asset.category})",
                     f"resources ({len(asset.names)}):"]
            lines += ['  ' + ln for ln in self._render_tree(asset.tree)]
            (out / f"{base}.manifest.txt").write_text('\n'.join(lines) + '\n', encoding='utf-8')

    def extract_all(self):
        if not self.win64_dir:
            return
        out = filedialog.askdirectory(title="Extract entire archive to...")
        if not out:
            return
        out = Path(out)

        def worker():
            self.pbar_var.set(0)
            files = list(fc.iter_asset_files(self.win64_dir))
            grand = len(files) or 1
            self.pbar.config(maximum=100)
            ok = err = 0
            for i, (subdir, sha1, fp) in enumerate(files):
                try:
                    data = fp.read_bytes()
                    asset = fc.open_asset(data, sha1, self.rsa, subdir)
                    if asset.payload is None:
                        err += 1
                        continue
                    sub_out = out / subdir
                    sub_out.mkdir(parents=True, exist_ok=True)
                    base = (f"{fc.safe_filename(asset.primary_name, 80)}__{sha1[:8]}"
                            if asset.is_named else sha1)
                    (sub_out / f"{base}{EXT_BY_KIND.get(asset.kind, '.bin')}").write_bytes(asset.payload)
                    ok += 1
                except Exception:
                    err += 1
                if i % 100 == 0:
                    self.pbar_var.set(int(i / grand * 100))
                    self.status.set(f"Extracting... {i:,}/{grand:,} (ok={ok:,} err={err})")
            self.pbar_var.set(100)
            self.status.set(f"Done. {ok:,} ok, {err:,} err -> {out}")
            messagebox.showinfo("Extract complete", f"OK: {ok:,}\nErrors: {err:,}\nOutput: {out}")

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------ background scan
    def scan_current_folder(self):
        sel = self.tree.selection()
        if not sel or not sel[0].startswith('sub:'):
            messagebox.showinfo("Scan", "Select a subfolder (00..0f) in the tree first.")
            return
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan", "Already scanning.")
            return
        subdir = sel[0][4:]
        self.scan_stop.clear()
        sd = self.win64_dir / subdir
        files = [f.name for f in sd.iterdir() if len(f.name) == 40]
        total = len(files)
        self.pbar.config(maximum=total)
        self.pbar_var.set(0)

        def worker():
            done = 0
            for sha1 in files:
                if self.scan_stop.is_set():
                    break
                done += 1
                if sha1 not in self.meta:
                    try:
                        self.decode(subdir, sha1)
                    except Exception:
                        pass
                m = self.meta.get(sha1)
                if m:
                    self.root.after(0, self._update_row, subdir, sha1, dict(m))
                if done % 40 == 0:
                    self.pbar_var.set(done)
                    self.status.set(f"Scanning {subdir}/ ... {done:,}/{total:,}")
            self.pbar_var.set(total)
            self.status.set(f"Scan complete: {subdir}/ ({done:,} files)")

        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()

    def _update_row(self, subdir, sha1, m):
        # update tree node label
        tn = f'file:{subdir}:{sha1}'
        if self.tree.exists(tn):
            try:
                self.tree.item(tn, text=self._file_label(sha1, m))
            except tk.TclError:
                pass
        # update list row
        liid = f'L-file:{subdir}:{sha1}'
        if self.flist.exists(liid):
            try:
                disp = m['primary'] if m.get('is_named') else f"{sha1[:16]}…"
                vals = list(self.flist.item(liid)['values'])
                vals[0] = disp
                vals[1] = m.get('kind', '')
                vals[2] = m.get('category', '')
                vals[3] = m.get('type_desc', '')
                vals[4] = m.get('num_names', '') or ''
                vals[6] = fc.fmt_size(m['payload_size']) if m.get('payload_size') else ''
                self.flist.item(liid, values=vals)
            except tk.TclError:
                pass


def main():
    root = tk.Tk()
    try:
        style = ttk.Style(root)
        if 'vista' in style.theme_names():
            style.theme_use('vista')
    except Exception:
        pass
    FreaExplorer(root)
    root.mainloop()


if __name__ == '__main__':
    main()
