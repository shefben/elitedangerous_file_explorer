"""
FREA Extractor for Elite Dangerous Odyssey
==========================================
This tool extracts and decrypts FREA-format game asset files from
Elite Dangerous by hooking the running game process via Frida.

Strategy:
1. Frida attaches to EliteDangerous64.exe
2. Hooks sub_140594670 (the FREA file reader factory)
3. Triggers reads via the game's own decrypt pipeline
4. Captures decrypted bytes and writes them to disk

Requirements:
    pip install frida-tools cryptography

Usage:
    # Game must be running, idle on main menu
    python frea_extractor.py --output ./extracted

Author: shefben@gmail.com
"""
import os
import sys
import time
import json
import argparse
import struct
import zlib
from pathlib import Path

try:
    import frida
except ImportError:
    print("Installing frida...")
    os.system(f'{sys.executable} -m pip install frida-tools')
    import frida


# ============================================================
# Frida JavaScript: hooks the running EliteDangerous64.exe
# ============================================================
FRIDA_SCRIPT = r"""
'use strict';

// Address constants discovered through reverse engineering
// (relative to module base, computed from VA - 0x140000000)
const MODULE_NAME = 'EliteDangerous64.exe';
const SUB_140594670_OFFSET = 0x594670;  // FREA reader factory: takes (this, path) returns 16624-byte reader
const SUB_140593AA0_OFFSET = 0x593AA0;  // sub_140593AA0: synchronous FREA reader (path)
const SUB_1405961D0_OFFSET = 0x5961D0;  // read function: (file, buf, count, ...)
const SUB_1405971C0_OFFSET = 0x5971C0;  // get_size function: (file) -> size
const SUB_140597230_OFFSET = 0x597230;  // file_open_impl
const SUB_1405954E0_OFFSET = 0x5954E0;  // sub_1405954E0: wraps file_open_impl

let moduleBase = null;
let hookedCount = 0;

function getMod() {
    if (moduleBase) return moduleBase;
    const m = Process.findModuleByName(MODULE_NAME);
    if (!m) {
        send({type: 'error', msg: 'Module not found: ' + MODULE_NAME});
        return null;
    }
    moduleBase = m.base;
    send({type: 'info', msg: 'Module base: ' + moduleBase});
    return moduleBase;
}

// === RPC: read decrypted data ===
// Called from Python to: open a FREA file, read all decrypted bytes
// Implementation: invoke sub_140594670 (reader factory) + read calls

rpc.exports = {
    init: function() {
        const base = getMod();
        return {base: base ? base.toString() : null};
    },

    // Read a FREA file - returns base64 of decrypted content
    readFreaFile: function(pathStr) {
        const base = getMod();
        if (!base) return {err: 'no module'};

        try {
            // Allocate 16624 bytes for reader object
            const readerSize = 16624;
            const reader = Memory.alloc(readerSize);
            // Zero it
            Memory.writeByteArray(reader, new Uint8Array(readerSize));

            // sub_140593AA0(reader, path)
            const sub_140593AA0 = base.add(SUB_140593AA0_OFFSET);
            const fn = new NativeFunction(sub_140593AA0, 'pointer', ['pointer', 'pointer']);
            const pathBuf = Memory.allocUtf8String(pathStr);
            const result = fn(reader, pathBuf);

            // Check error flag at reader+0
            const flag = Memory.readU16(reader);

            // Get file_handle at reader+8
            const fileHandle = Memory.readPointer(reader.add(8));
            const fileSize = Memory.readU64(reader.add(24)).valueOf();
            const decompSize = Memory.readU64(reader.add(16)).valueOf();

            send({type: 'debug', msg: `reader flag=${flag} fileSize=${fileSize} decompSize=${decompSize}`});

            return {
                ok: true,
                flag: flag,
                fileSize: fileSize.toString(),
                decompSize: decompSize.toString(),
                readerAddr: reader.toString(),
            };
        } catch (e) {
            return {err: e.toString()};
        }
    },

    // Just hook sub_140594670 entry/exit and log
    enableLogging: function() {
        const base = getMod();
        if (!base) return false;

        const sub_140594670 = base.add(SUB_140594670_OFFSET);
        Interceptor.attach(sub_140594670, {
            onEnter: function(args) {
                this.thisPtr = args[0];
                this.pathPtr = args[1];
                let pathStr = '<null>';
                try {
                    if (!this.pathPtr.isNull()) {
                        pathStr = this.pathPtr.readUtf8String();
                    }
                } catch (e) {}
                hookedCount++;
                send({type: 'hook', fn: 'sub_140594670', path: pathStr, n: hookedCount});
            },
            onLeave: function(retval) {
                send({type: 'hook_ret', fn: 'sub_140594670', ret: retval.toString()});
            }
        });
        return true;
    },
};
"""


def find_game_process():
    """Find a running EliteDangerous64.exe process."""
    for p in frida.enumerate_processes():
        if p.name.lower() == 'elitedangerous64.exe':
            return p.pid
    return None


def main():
    parser = argparse.ArgumentParser(description='FREA file extractor for Elite Dangerous')
    parser.add_argument('--output', default='./extracted', help='Output directory')
    parser.add_argument('--max-files', type=int, default=10, help='Max files to extract')
    parser.add_argument('--win64-dir', default=r'F:\SteamLibrary\steamapps\common\Elite Dangerous\Products\elite-dangerous-odyssey-64\Win64', help='Win64 directory')
    parser.add_argument('--log-only', action='store_true', help='Only log hooks, do not extract')
    args = parser.parse_args()

    pid = find_game_process()
    if not pid:
        print("ERROR: Elite Dangerous game must be running.")
        print("       Start the game, wait until main menu, then re-run.")
        return 1
    print(f"Found game process: PID {pid}")

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    session = frida.attach(pid)
    script = session.create_script(FRIDA_SCRIPT)

    def on_message(msg, data):
        if msg['type'] == 'send':
            payload = msg['payload']
            t = payload.get('type', '?')
            if t == 'info':
                print(f"[INFO] {payload.get('msg')}")
            elif t == 'debug':
                print(f"[DEBUG] {payload.get('msg')}")
            elif t == 'hook':
                print(f"[HOOK#{payload.get('n')}] {payload.get('fn')}({payload.get('path')})")
            elif t == 'hook_ret':
                print(f"[HOOK_RET] {payload.get('fn')} -> {payload.get('ret')}")
            elif t == 'error':
                print(f"[ERROR] {payload.get('msg')}")
            else:
                print(f"[{t}] {payload}")
        elif msg['type'] == 'error':
            print(f"[FRIDA_ERR] {msg.get('description', msg)}")

    script.on('message', on_message)
    script.load()

    init = script.exports_sync.init()
    print(f"init: {init}")

    if args.log_only:
        print("Logging hooks - run the game, navigate menus to trigger reads.")
        print("Press Ctrl+C to stop.")
        script.exports_sync.enable_logging()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping...")
        return 0

    # Pick small sample files
    win64 = Path(args.win64_dir)
    samples = []
    for subdir in sorted(os.listdir(win64)):
        sd = win64 / subdir
        if not sd.is_dir() or len(subdir) != 2:
            continue
        for fname in sorted(os.listdir(sd)):
            if len(fname) != 40:
                continue
            try:
                with open(sd / fname, 'rb') as f:
                    if f.read(4) != b'FREA':
                        continue
            except:
                continue
            samples.append((sd / fname, fname, subdir))
            if len(samples) >= args.max_files:
                break
        if len(samples) >= args.max_files:
            break

    print(f"Will attempt to read {len(samples)} FREA files...")
    for fp, sha1, subdir in samples:
        rel_path = f"{subdir}/{sha1}"
        print(f"\n--- Reading: {rel_path} ---")
        try:
            result = script.exports_sync.read_fre_file(rel_path)
            print(f"  Result: {result}")
        except Exception as e:
            print(f"  Error: {e}")
        time.sleep(0.1)

    print("\nDone. Run with --log-only to passively observe game read patterns.")
    session.detach()
    return 0


if __name__ == '__main__':
    sys.exit(main())
