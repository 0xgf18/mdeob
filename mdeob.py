#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCLOCK DE-OBFUSCATOR v1.0  (Termux / Windows / Linux)

An "overpowered" APK deobfuscator. It:

  1. analyze   - pure-python (stdlib only) deep scan of classes*.dex:
                 R8 flatten/repack detection, XOR string-decryptor recovery,
                 SHA-256 "CreditGuard"-style integrity gate detection,
                 obfuscated constant resolution.
  2. deob      - full pipeline: baksmali disassembly -> decode XYC constants
                 -> auto class rename -> neutralize integrity gates ->
                 smali reassembly -> APK rebuild (optional sign).
  3. rebuild   - repack an APK from a modified dex (drops old signature block).
  4. sign      - sign an APK with apksigner.

No third-party pip packages required. Java + smali/baksmali jars are used only
by the `deob` command for text-level rewriting; `analyze` works everywhere a
python3 exists.

Author: MCLOCK RESEARCH
"""

import argparse
import base64
import hashlib
import io
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import zipfile

VERSION = "1.0.0"
NAME = "MCLOCK DE-OBFUSCATOR"
R8_SRC = re.compile(r"r8-map-id-[0-9a-f]+")

# Bundled resources (filled by build_bundle.py). Leave empty in dev copy.
BUNDLED = {}


def _bundle_resources():
    """Extract bundled jars/keystore next to the script (runtime/) once."""
    if not BUNDLED:
        return {}
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runtime")
    try:
        os.makedirs(base, exist_ok=True)
    except Exception:
        base = os.path.join(tempfile.gettempdir(), "mdeob_runtime")
        os.makedirs(base, exist_ok=True)
    out = {}
    for name, b64 in BUNDLED.items():
        p = os.path.join(base, name)
        try:
            if not (os.path.exists(p) and os.path.getsize(p) > 0):
                with open(p, "wb") as f:
                    f.write(base64.b64decode(b64))
            out[name] = p
        except Exception:
            pass
    return out

# --------------------------------------------------------------------------
# logging helpers
# --------------------------------------------------------------------------

VERBOSE = False


def _is_tty():
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _c(code, s):
    if not _is_tty():
        return s
    return "\x1b[%sm%s\x1b[0m" % (code, s)


class Log:
    on = True
    @staticmethod
    def _fmt(a):
        if len(a) == 1:
            return str(a[0])
        if isinstance(a[0], str) and "%" in a[0]:
            try:
                return a[0] % a[1:]
            except Exception:
                pass
        return " ".join(str(x) for x in a)
    def info(self, *a):
        if self.on:
            print(_c("36", "[*]"), self._fmt(a))
    def ok(self, *a):
        if self.on:
            print(_c("32", "[+]"), self._fmt(a))
    def warn(self, *a):
        if self.on:
            print(_c("33", "[!]"), self._fmt(a))
    def err(self, *a):
        if self.on:
            print(_c("31", "[-]"), self._fmt(a))
    def raw(self, s):
        if self.on:
            print(s)


log = Log()

SPIN = "-\\|/"


class Task:
    """One-line live progress indicator. Spinner only on TTY, otherwise a
    silent two-line (start/done) log. 'task ok' message is the visible
    result, so commands stay quiet while work is running."""

    def __init__(self, label):
        self.label = label
        self._stop = threading.Event()
        self._th = None
        if _is_tty():
            self._write("\r" + self._line(0))
            self._th = threading.Thread(target=self._spin, daemon=True)
            self._th.start()
        else:
            print(_c("36", "[>]"), label, "...")

    def _line(self, i):
        return "[%s] %s" % (SPIN[i % 4], self.label)

    def _write(self, s):
        try:
            sys.stdout.write(s)
            sys.stdout.flush()
        except Exception:
            pass

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            self._write("\r" + self._line(i))
            i += 1
            self._stop.wait(0.12)

    def ok(self, msg=None, mark="[+]"):
        self._stop.set()
        if self._th:
            self._th.join()
        tail = self.label + (" - " + msg if msg else "")
        if _is_tty():
            self._write("\r" + _c("32", mark) + " " + tail + "\x1b[K\n")
        else:
            print(_c("32", mark), tail)
        sys.stdout.flush()

    def fail(self, msg=None):
        self._stop.set()
        if self._th:
            self._th.join()
        tail = self.label + (" - " + msg if msg else "")
        if _is_tty():
            self._write("\r" + _c("31", "[-]") + " " + tail + "\x1b[K\n")
        else:
            print(_c("31", "[-]"), tail)
        sys.stdout.flush()

# --------------------------------------------------------------------------
# modified-UTF8 / uleb helpers
# --------------------------------------------------------------------------

def uleb128(b, off):
    result = 0
    shift = 0
    while True:
        byte = b[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return result, off

def sleb128(b, off):
    result = 0
    shift = 0
    while True:
        byte = b[off]
        off += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            if shift < 32 and (byte & 0x40):
                result |= -(1 << shift)
            break
    return result, off

def mod_utf8(b, off):
    """decode a modified-UTF8 string (with 16-bit supplementary pairs)."""
    size, off = uleb128(b, off)
    out = []
    while size:
        c = b[off]
        off += 1
        size -= 1
        if c & 0x80:
            c2 = b[off]; off += 1; size -= 1
            if (c & 0xE0) == 0xC0:
                out.append(chr(((c & 0x1F) << 6) | (c2 & 0x3F)))
            else:
                c3 = b[off]; off += 1; size -= 1
                cp = ((c & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F)
                if 0xD800 <= cp <= 0xDFFF:
                    c4 = b[off]; off += 1; size -= 1
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (c4 - 0xDC00)
                out.append(chr(cp))
        else:
            out.append(chr(c))
    return "".join(out), off

# --------------------------------------------------------------------------
# minimal raw DEX reader (stdlib only)
# --------------------------------------------------------------------------

class Dex:
    """Reads strings/types/protos/fields/methods/class-defs/code from a dex."""

    OP_FMT = {
        0x00: "10x", 0x01: "12x", 0x02: "22x", 0x03: "32x",
        0x04: "12x", 0x05: "22x", 0x06: "32x", 0x07: "12x",
        0x08: "22x", 0x09: "32x",
        0x0a: "11x", 0x0b: "11x", 0x0c: "11x", 0x0d: "11x",
        0x0e: "10x", 0x0f: "11x", 0x10: "11x", 0x11: "11x",
        0x12: "11n", 0x13: "21s", 0x14: "31i", 0x15: "21h",
        0x16: "21s", 0x17: "31i", 0x18: "51l", 0x19: "21h",
        0x1a: "21c", 0x1b: "31c", 0x1c: "21c",
        0x1d: "10x", 0x1e: "10x", 0x1f: "22c", 0x20: "22c",
        0x21: "12x", 0x22: "21c", 0x23: "22c",
        0x24: "35c", 0x25: "3rc", 0x26: "31t",
        0x27: "10x", 0x28: "10t", 0x29: "20t", 0x2a: "30t",
        0x2b: "31t", 0x2c: "31t",
        0x2d: "23x", 0x2e: "23x", 0x2f: "23x", 0x30: "23x",
        0x31: "23x",
        0x32: "22t", 0x33: "22t", 0x34: "22t", 0x35: "22t",
        0x36: "22t", 0x37: "22t",
        0x38: "21t", 0x39: "21t", 0x3a: "21t", 0x3b: "21t",
        0x3c: "21t", 0x3d: "21t",
        0x3e: "23x", 0x3f: "23x", 0x40: "23x", 0x41: "23x",
        0x42: "23x", 0x43: "23x", 0x44: "23x",
        0x45: "23x", 0x46: "23x", 0x47: "23x", 0x48: "23x",
        0x49: "23x", 0x4a: "23x", 0x4b: "23x",
        0x4c: "22c", 0x4d: "22c", 0x4e: "22c", 0x4f: "22c",
        0x50: "22c", 0x51: "22c", 0x52: "22c",
        0x53: "22c", 0x54: "22c", 0x55: "22c", 0x56: "22c",
        0x57: "22c", 0x58: "22c", 0x59: "22c",
        0x5a: "21c", 0x5b: "21c", 0x5c: "21c", 0x5d: "21c",
        0x5e: "21c", 0x5f: "21c", 0x60: "21c",
        0x61: "21c", 0x62: "21c", 0x63: "21c", 0x64: "21c",
        0x65: "21c", 0x66: "21c", 0x67: "21c",
        0x68: "21c", 0x69: "21c", 0x6a: "21c", 0x6b: "21c",
        0x6c: "21c", 0x6d: "21c",
        0x6e: "35c", 0x6f: "35c", 0x70: "35c",
        0x71: "35c", 0x72: "35c", 0x73: "35c",
        0x74: "3rc", 0x75: "3rc", 0x76: "3rc", 0x77: "3rc",
        0x78: "3rc",
        0x79: "12x", 0x7a: "12x", 0x7b: "12x", 0x7c: "12x",
        0x7d: "12x", 0x7e: "12x",
        0x7f: "12x", 0x80: "12x", 0x81: "12x", 0x82: "12x",
        0x83: "12x", 0x84: "12x", 0x85: "12x", 0x86: "12x",
        0x87: "12x", 0x88: "12x", 0x89: "12x", 0x8a: "12x",
        0x8b: "12x", 0x8c: "12x", 0x8d: "12x",
        0x8e: "23x", 0x8f: "23x", 0x90: "23x", 0x91: "23x",
        0x92: "23x", 0x93: "23x", 0x94: "23x", 0x95: "23x",
        0x96: "23x", 0x97: "23x", 0x98: "23x",
        0x99: "23x", 0x9a: "23x", 0x9b: "23x", 0x9c: "23x",
        0x9d: "23x", 0x9e: "23x", 0x9f: "23x",
        0xa0: "23x", 0xa1: "23x", 0xa2: "23x", 0xa3: "23x",
        0xa4: "23x", 0xa5: "23x",
        0xa6: "12x", 0xa7: "12x", 0xa8: "12x",
        0xa9: "12x", 0xaa: "12x", 0xab: "12x", 0xac: "12x",
        0xad: "12x", 0xae: "12x", 0xaf: "12x", 0xb0: "12x",
        0xb1: "12x", 0xb2: "12x",
        0xb3: "12x", 0xb4: "12x", 0xb5: "12x", 0xb6: "12x",
        0xb7: "12x", 0xb8: "12x", 0xb9: "12x",
        0xba: "12x", 0xbb: "23x", 0xbc: "23x", 0xbd: "23x",
        0xbe: "23x", 0xbf: "23x",
        0xc0: "23x", 0xc1: "23x", 0xc2: "23x", 0xc3: "23x",
        0xc4: "23x", 0xc5: "23x",
        0xc6: "23x", 0xc7: "23x", 0xc8: "23x", 0xc9: "23x",
        0xca: "23x", 0xcb: "23x",
        0xcc: "23x", 0xcd: "12x", 0xce: "22s", 0xcf: "22b",
        0xd0: "22s", 0xd1: "22b",
        0xd2: "22s", 0xd3: "22b", 0xd4: "22s", 0xd5: "22b",
        0xd6: "22s", 0xd7: "22s",
        0xd8: "22b", 0xd9: "22s", 0xda: "22b", 0xdb: "22s",
        0xdc: "22b", 0xdd: "22s", 0xde: "22b",
        0xdf: "12x", 0xe0: "12x", 0xe1: "12x", 0xe2: "12x",
        0xe3: "23x", 0xe4: "23x", 0xe5: "23x",
        0xe6: "23x", 0xe7: "23x", 0xe8: "23x", 0xe9: "23x",
        0xea: "23x", 0xeb: "23x", 0xec: "23x",
        0xed: "12x", 0xee: "12x", 0xef: "12x", 0xf0: "12x",
        0xf1: "12x", 0xf2: "12x", 0xf3: "12x",
        0xf4: "12x", 0xf5: "12x", 0xf6: "12x", 0xf7: "12x",
        0xf8: "12x", 0xf9: "12x", 0xfa: "12x",
        0xfb: "3rc", 0xfc: "35c",
        0xfd: "35c", 0xfe: "35c", 0xff: "35c",
    }

    def __init__(self, data, name="classes.dex"):
        self.name = name
        self.d = data
        if data[0:4] != b"dex\n":
            raise ValueError("%s: not a dex file" % name)
        ver = data[4:8]
        self.version = ver.decode("latin1")
        if self.version not in ("035\x00", "037\x00", "038\x00", "039\x00", "040\x00", "041\x00"):
            log.warn("unusual dex version %r", self.version)
        self.string_ids_size = struct.unpack_from("<I", data, 56)[0]
        self.string_ids_off = struct.unpack_from("<I", data, 60)[0]
        self.type_ids_size = struct.unpack_from("<I", data, 64)[0]
        self.type_ids_off = struct.unpack_from("<I", data, 68)[0]
        self.proto_ids_size = struct.unpack_from("<I", data, 72)[0]
        self.proto_ids_off = struct.unpack_from("<I", data, 76)[0]
        self.field_ids_size = struct.unpack_from("<I", data, 80)[0]
        self.field_ids_off = struct.unpack_from("<I", data, 84)[0]
        self.method_ids_size = struct.unpack_from("<I", data, 88)[0]
        self.method_ids_off = struct.unpack_from("<I", data, 92)[0]
        self.class_defs_size = struct.unpack_from("<I", data, 96)[0]
        self.class_defs_off = struct.unpack_from("<I", data, 100)[0]
        self.data_size = struct.unpack_from("<I", data, 104)[0]
        self.data_off = struct.unpack_from("<I", data, 108)[0]
        self._strings = [None] * self.string_ids_size
        self._types = [None] * self.type_ids_size
        self.string_ids_size = self.string_ids_size
        self._fields = None
        self._methods = None

    # -- pools -----------------------------------------------------------
    def string(self, idx):
        if self._strings[idx] is not None:
            return self._strings[idx]
        off = struct.unpack_from("<I", self.d, self.string_ids_off + idx * 4)[0]
        s, _ = mod_utf8(self.d, off)
        self._strings[idx] = s
        return s

    def type(self, idx):
        if self._types[idx] is not None:
            return self._types[idx]
        doff = struct.unpack_from("<I", self.d, self.type_ids_off + idx * 4)[0]
        s = self.string(doff)
        self._types[idx] = s
        return s

    def field(self, idx):
        if self._fields is None:
            self._fields = []
            for i in range(self.field_ids_size):
                off = self.field_ids_off + i * 8
                cls = struct.unpack_from("<H", self.d, off)[0]
                typ = struct.unpack_from("<H", self.d, off + 2)[0]
                nid = struct.unpack_from("<I", self.d, off + 4)[0]
                self._fields.append((cls, typ, self.string(nid)))
        return self._fields[idx]

    def method(self, idx):
        if self._methods is None:
            self._methods = []
            for i in range(self.method_ids_size):
                off = self.method_ids_off + i * 8
                cls = struct.unpack_from("<H", self.d, off)[0]
                pid = struct.unpack_from("<H", self.d, off + 2)[0]
                nid = struct.unpack_from("<I", self.d, off + 4)[0]
                self._methods.append((cls, pid, self.string(nid)))
        return self._methods[idx]

    def proto(self, idx):
        off = self.proto_ids_off + idx * 12
        shorty = struct.unpack_from("<I", self.d, off)[0]
        ret = struct.unpack_from("<I", self.d, off + 4)[0]
        params_off = struct.unpack_from("<I", self.d, off + 8)[0]
        params = []
        if params_off:
            size = struct.unpack_from("<I", self.d, params_off)[0]
            for i in range(size):
                params.append(struct.unpack_from("<H", self.d, params_off + 4 + i * 2)[0])
        return self.type(ret), [self.type(p) for p in params]

    # -- class defs ------------------------------------------------------
    def class_defs(self):
        out = []
        for i in range(self.class_defs_size):
            off = self.class_defs_off + i * 32
            cls_idx = struct.unpack_from("<I", self.d, off)[0]
            access = struct.unpack_from("<I", self.d, off + 4)[0]
            sup = struct.unpack_from("<I", self.d, off + 8)[0]
            iface_off = struct.unpack_from("<I", self.d, off + 12)[0]
            src = struct.unpack_from("<I", self.d, off + 16)[0]
            annot_off = struct.unpack_from("<I", self.d, off + 20)[0]
            class_data_off = struct.unpack_from("<I", self.d, off + 24)[0]
            static_off = struct.unpack_from("<I", self.d, off + 28)[0]
            name = self.type(cls_idx)
            srcname = self.string(src) if src != 0xFFFFFFFF else None
            out.append({
                "name": name,
                "access": access,
                "super": self.type(sup) if sup != 0xFFFFFFFF else None,
                "source": srcname,
                "class_data_off": class_data_off,
                "static_off": static_off,
            })
        return out

    def methods_of(self, cls):
        cdo = cls["class_data_off"]
        if not cdo:
            return []
        d = self.d
        off = cdo
        sf, off = uleb128(d, off)     # static_fields_size
        inf, off = uleb128(d, off)    # instance_fields_size
        dm, off = uleb128(d, off)     # direct_methods_size
        vm, off = uleb128(d, off)     # virtual_methods_size
        for _ in range(sf + inf):
            off = uleb128(d, off)[1]  # field_idx diff
            off = uleb128(d, off)[1]  # access flags
        # walk methods (direct and virtual lists each start idx accumulation at 0)
        idx = 0
        meths = []
        n_methods = dm + vm
        for _ in range(n_methods):
            if _ == dm:
                idx = 0
            dif, off = uleb128(d, off)
            idx += dif
            acc, off = uleb128(d, off)
            code_off, off = uleb128(d, off)
            meth = self.method(idx)
            cls_t = self.type(meth[0])
            ret, params = self.proto(meth[1])
            meths.append({
                "idx": idx,
                "name": meth[2],
                "class": cls_t,
                "ret": ret,
                "params": params,
                "access": acc,
                "code_off": code_off,
            })
        return meths

    def code(self, code_off):
        if not code_off:
            return None
        d = self.d
        regs = struct.unpack_from("<H", d, code_off)[0]
        ins = struct.unpack_from("<H", d, code_off + 2)[0]
        outs = struct.unpack_from("<H", d, code_off + 4)[0]
        tries = struct.unpack_from("<H", d, code_off + 6)[0]
        debug_off = struct.unpack_from("<I", d, code_off + 8)[0]
        insns_size = struct.unpack_from("<I", d, code_off + 12)[0]
        insns_off = code_off + 16
        return {
            "regs": regs, "ins": ins, "outs": outs, "tries": tries,
            "insns_size": insns_size, "insns_off": insns_off,
        }

def uleb128_bytes(b):
    v, _ = uleb128(b, 0)
    return v, 0

# --------------------------------------------------------------------------
# instruction parsing
# --------------------------------------------------------------------------

def parse_insns(d, code, class_to_string=None):
    """Yield (addr, op, fmt, operand-words) pairs, tracking 16-bit code units."""
    bb = d
    off = code["insns_off"]
    end = off + code["insns_size"] * 2
    kri = {}
    n = 0
    while off < end:
        u = struct.unpack_from("<H", bb, off)[0]
        op = u & 0xFF
        addr = off - code["insns_off"]
        fmt = Dex.OP_FMT.get(op, "?")
        words = 1
        oper = []
        if fmt == "10x" or fmt == "10t":
            pass
        elif fmt == "12x":
            a = (u >> 8) & 0xF
            b = (u >> 12) & 0xF
            oper = ["v%d" % a, "v%d" % b]
        elif fmt == "11x":
            oper = ["v%d" % (u >> 8)]
        elif fmt == "11n":
            a = (u >> 8) & 0xF
            b = (u >> 12) & 0xF
            oper = ["v%d" % a, raw_signed_nib(b)]
        elif fmt == "22x":
            a = (u >> 8) & 0xFF
            b = struct.unpack_from("<H", bb, off + 2)[0]
            words = 2
            oper = ["v%d" % a, "v%d" % b]
        elif fmt == "21s":
            a = (u >> 8) & 0xFF
            b = struct.unpack_from("<h", bb, off + 2)[0]
            words = 2
            oper = ["v%d" % a, b]
        elif fmt == "21h":
            a = (u >> 8) & 0xFF
            b = struct.unpack_from("<H", bb, off + 2)[0]
            words = 2
            if op in (0x15,):
                b = b << 16
                if b & 0x80000000:
                    b -= 0x100000000
            elif op == 0x19:
                b = b << 48
                if b & 0x8000000000000000:
                    b -= 0x10000000000000000
            oper = ["v%d" % a, b]
        elif fmt == "21c":
            a = (u >> 8) & 0xFF
            b = struct.unpack_from("<H", bb, off + 2)[0]
            words = 2
            oper = ["v%d" % a, b]
            n += 1
            kri[n] = (op, a, b)
        elif fmt == "31i":
            a = (u >> 8) & 0xFF
            b = struct.unpack_from("<i", bb, off + 2)[0]
            words = 3
            oper = ["v%d" % a, b]
        elif fmt == "31c":
            a = (u >> 8) & 0xFF
            b = struct.unpack_from("<I", bb, off + 2)[0]
            words = 3
            oper = ["v%d" % a, b]
        elif fmt == "51l":
            a = (u >> 8) & 0xFF
            b = struct.unpack_from("<q", bb, off + 2)[0]
            words = 5
            oper = ["v%d" % a, b]
        elif fmt == "22c":
            a = (u >> 8) & 0xFF
            b = (u >> 12) & 0xFF
            c = struct.unpack_from("<H", bb, off + 2)[0]
            words = 2
            oper = ["v%d" % a, "v%d" % b, c]
        elif fmt == "23x":
            a = (u >> 8) & 0xFF
            b = (u >> 12) & 0xFF
            c2 = struct.unpack_from("<H", bb, off + 2)[0]
            words = 2
            oper = ["v%d" % a, "v%d" % b, "v%d" % c2]
        elif fmt == "35c":
            a = (u >> 8) & 0xF
            b = (u >> 12) & 0xF
            c = struct.unpack_from("<H", bb, off + 2)[0]
            regs = []
            for i in range(min(a, 4)):
                regs.append((u >> (16 + i * 4)) & 0xF)
            if a >= 5:
                regs.append((struct.unpack_from("<H", bb, off + 4)[0]) & 0xF)
            words = 3 if a >= 5 else 2
            oper = ["v%d" % r for r in regs] + [c]
            if op in (0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d):
                n += 1
                kri[n] = (op, a, c)
        elif fmt == "3rc":
            a = (u >> 8) & 0xFF
            c = struct.unpack_from("<H", bb, off + 2)[0]
            words = 2
            n += 1
            kri[n] = (op, a, c)
            oper = ["r%d" % (struct.unpack_from("<H", bb, off + 4)[0]), a, c]
        elif fmt == "20t" or fmt == "30t":
            words = 2 if fmt == "20t" else 3
        elif fmt == "21t":
            a = (u >> 8) & 0xFF
            b = struct.unpack_from("<h", bb, off + 2)[0]
            words = 2
            oper = ["v%d" % a, b]
        elif fmt == "22t":
            a = (u >> 8) & 0xFF
            b = (u >> 12) & 0xFF
            c = struct.unpack_from("<h", bb, off + 2)[0]
            words = 2
            oper = ["v%d" % a, "v%d" % b, c]
        elif fmt == "31t":
            a = (u >> 8) & 0xFF
            b = struct.unpack_from("<i", bb, off + 2)[0]
            words = 3
            oper = ["v%d" % a, b]
        elif fmt == "22s":
            a = (u >> 8) & 0xFF
            b = (u >> 12) & 0xFF
            c = struct.unpack_from("<h", bb, off + 2)[0]
            words = 2
            oper = ["v%d" % a, "v%d" % b, c]
        elif fmt == "22b":
            a = (u >> 8) & 0xFF
            b = (u >> 12) & 0xFF
            c = struct.unpack_from("<b", bb, off + 2)[0]
            words = 2
            oper = ["v%d" % a, "v%d" % b, c]
        else:
            words = 1
        yield addr, op, fmt, oper, kri.get(n, None)
        off += words * 2

def raw_signed_nib(v):
    v &= 0xF
    if v & 0x8:
        v -= 0x10
    return v

def const_payload(d, op, oper, dex=None):
    """Return Python value for a const-ish op, else ('ref', token)."""
    if op == 0x12:
        return oper[1]
    if op in (0x13, 0x15):
        return oper[1]
    if op == 0x14:
        return oper[1]
    if op in (0x16,):
        return oper[1]
    if op == 0x17:
        return oper[1]
    if op == 0x18:
        return oper[1]
    if op == 0x19:
        return oper[1]
    if op == 0x1a and dex:
        return ("str", dex.string(oper[1]))
    if op == 0x1c and dex:
        return ("cls", dex.type(oper[1]))
    return ("unsup", None)

# --------------------------------------------------------------------------
# static array recovery
# --------------------------------------------------------------------------

def read_array_payload(d, data_off):
    """Read a fill-array-data payload at data_off: (ident,width,size,values ints)."""
    if data_off < 0 or data_off + 8 > len(d):
        raise ValueError("bad array payload offset %d" % data_off)
    ident = struct.unpack_from("<H", d, data_off)[0]
    width = struct.unpack_from("<H", d, data_off + 2)[0]
    size = struct.unpack_from("<I", d, data_off + 4)[0]
    # accepted: spec 0x0003 and the byte-swapped 0x0300 seen in R8 output
    if ident not in (0x0003, 0x0300) or width not in (1, 2, 4, 8):
        raise ValueError("not a fill-array-data payload (ident=%#x width=%d)" % (ident, width))
    if size > 1 << 24:
        raise ValueError("array payload size implausible (%d)" % size)
    need = 8 + size * width
    if data_off + need > len(d):
        raise ValueError("array payload overruns dex")
    vals = []
    for i in range(size):
        if width == 1:
            vals.append(d[data_off + 8 + i])
        elif width == 2:
            vals.append(struct.unpack_from("<H", d, data_off + 8 + i * 2)[0])
        elif width == 4:
            vals.append(struct.unpack_from("<I", d, data_off + 8 + i * 4)[0])
        elif width == 8:
            vals.append(struct.unpack_from("<Q", d, data_off + 8 + i * 8)[0])
    return width, vals

class ClassScan:
    """Recover static int arrays + XOR-decryptable strings from one class."""

    def __init__(self, dex, cls):
        self.dex = dex
        self.cls = cls
        self.arrays = {}        # field-> list of ints
        self.decode_candidates = []  # list of (methodname, ret, params)

    def scan(self):
        meths = self.dex.methods_of(self.cls)
        clinit = [m for m in meths if m["name"] == "<clinit>"]
        # decode fill-array-data inside clinit (static field init)
        for m in clinit:
            self._decode_clinit(m)
        for m in meths:
            if m["name"] in ("<clinit>", "<init>"):
                continue
            self.decode_candidates.append(m)
        return self

    def _decode_clinit(self, m):
        code = self.dex.code(m["code_off"])
        if not code:
            return
        regs = {}
        d = self.dex.d
        for addr, op, fmt, oper, kri in parse_insns(d, code, None):
            if op == 0x26 and len(oper) == 2:  # fill-array-data vAA, offset
                r = oper[0]
                rel = oper[1]
                payload_off = code["insns_off"] + addr + rel * 2
                width, vals = read_array_payload(d, payload_off)
                regs[r] = ("arr", width, vals)
            elif op in (0x5d,) and len(oper) == 2:  # sput-boolean
                pass
            elif op in (0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d) and len(oper) == 2:
                # sput-* : oper[0] = register, oper[1] = field index (21c)
                if kri and kri[0] in (0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d):
                    _, a, fidx = kri
                    reg = "v%d" % a
                    if reg in regs and regs[reg][0] == "arr":
                        cls_t, _, fname = self.dex.field(fidx)
                        self.arrays[fname] = regs[reg][2]
                else:
                    fidx = oper[1]
                    reg = oper[0]
                    if reg in regs and regs[reg][0] == "arr":
                        try:
                            cls_t, _, fname = self.dex.field(fidx)
                            self.arrays[fname] = regs[reg][2]
                        except Exception:
                            pass
            elif op == 0x7 and len(oper) == 2:
                regs[oper[0]] = regs.get(oper[1])

    def xor_strings(self):
        """Try every pair of int arrays as (cipher,key)."""
        out = []
        arrs = list(self.arrays.items())
        for n1, (f1, v1) in enumerate(arrs):
            for n2, (f2, v2) in enumerate(arrs):
                if n1 == n2:
                    continue
                if not v1 or not v2:
                    continue
                try:
                    s = decode_xor(v1, v2)
                except Exception:
                    continue
                if printable(s, min_ratio=0.7) and len(s) >= 2:
                    out.append((f1, f2, s))
        return out

def decode_xor(cipher, key):
    klen = len(key)
    out = []
    for i, c in enumerate(cipher):
        out.append(c ^ key[i % klen])
    return bytes(out).decode("latin1")

def printable(s, min_ratio=0.6):
    if not s:
        return False
    good = sum(1 for ch in s if 0x20 <= ord(ch) <= 0x7e or ch in "\n\r\t")
    if len(s) and good / len(s) >= min_ratio:
        return any(ch.isalnum() for ch in s)
    return False

# --------------------------------------------------------------------------
# integrity-gate detection (SHA-256 CreditGuard pattern)
# --------------------------------------------------------------------------

SHA_STR = "SHA-256"
RE_HEX64 = re.compile(r"^[0-9a-f]{64}$")
RE_USES_SHA = re.compile(r"SHA-256")

def scan_integrity(dex, cls):
    """Detect MessageDigest==const(64hex) -> failure flows with English strings."""
    findings = []
    for m in dex.methods_of(cls):
        code = dex.code(m["code_off"])
        if not code:
            continue
        has_sha = False
        digests = []
        strs = []
        for addr, op, fmt, oper, kri in parse_insns(dex.d, code, None):
            if op == 0x1a:
                s = dex.string(oper[1])
                if s == SHA_STR:
                    has_sha = True
                elif RE_HEX64.match(s):
                    digests.append(s)
                if s and printable(s):
                    strs.append(s)
        if has_sha and digests:
            ctx = [s for s in strs if "integrity" in s.lower() or "modif" in s.lower()
                   or "credit" in s.lower() or "crack" in s.lower() or "uninstall" in s.lower()
                   or s in ("SHA-256",)]
            findings.append({
                "class": cls["name"],
                "method": m["name"],
                "ret": m["ret"],
                "sha256_hex_constants": digests,
                "hints": ctx[:12],
            })
    return findings

# --------------------------------------------------------------------------
# APK layer
# --------------------------------------------------------------------------

def iter_dex_entries(apk_path):
    z = zipfile.ZipFile(apk_path)
    names = sorted({"classes.dex", *[
        n for n in z.namelist()
        if re.match(r"^classes\d+\.dex$", n)
    ]})
    for n in names:
        try:
            yield n, z.read(n)
        except Exception as e:
            log.warn("cannot read %s: %s", n, e)
    z.close()

def safe_name(p):
    return re.sub(r"[^A-Za-z0-9_.\- ]", "_", p)

# --------------------------------------------------------------------------
# analyze command
# --------------------------------------------------------------------------

def cmd_analyze(args):
    report = {"tool": NAME, "version": VERSION, "apks": []}
    for apk in args.apk:
        log.info("analyzing %s", apk)
        a = {"path": apk, "dexs": []}
        for name, data in iter_dex_entries(apk):
            log.info("  %s (%d bytes)", name, len(data))
            d = Dex(data, name)
            cls = d.class_defs()
            x = {
                "file": name,
                "classes": len(cls),
                "r8_flattened": 0,
                "xor_classes": 0,
                "xor_strings": [],
                "integrity_gates": [],
                "sources_r8": 0,
                "root_classes": 0,
            }
            for c in cls:
                if R8_SRC.search(c["source"] or ""):
                    x["sources_r8"] += 1
                if c["name"].startswith("L") and c["name"].count("/") == 0:
                    if 4 <= len(c["name"]) <= 5:
                        x["root_classes"] += 1
                try:
                    cs = ClassScan(d, c).scan()
                except Exception:
                    continue
                try:
                    strs = cs.xor_strings()
                    for f1, f2, s in strs[:8]:
                        x["xor_strings"].append({"class": c["name"], "cipher": f1,
                                                 "key": f2, "decoded": s})
                    x["xor_strings"].extend({"class": c["name"], "cipher": f1,
                                             "key": f2, "decoded": s}
                                            for f1, f2, s in strs[8:])
                    if strs:
                        x["xor_classes"] += 1
                except Exception:
                    strs = []
            for c in cls:
                try:
                    cs = ClassScan(d, c).scan()
                    gates = scan_integrity(d, c)
                except Exception:
                    continue
                if gates:
                    x["integrity_gates"].extend(gates)
            if args.scan_methods:
                for c in cls:
                    m = d.methods_of(c)
                    x["method_count"] = x.get("method_count", 0) + len(m)
                    x["classes"] = x["classes"]
            a["dexs"].append(x)
        report["apks"].append(a)
    if args.json:
        with io.open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        log.ok("report written to %s", args.json)
    else:
        fmt_report(report)

def fmt_report(report):
    log.raw("=" * 72)
    log.raw(" %s v%s" % (NAME, VERSION))
    log.raw("=" * 72)
    for apk in report["apks"]:
        log.raw("\nAPK: %s" % apk["path"])
        for x in apk["dexs"]:
            log.raw("  dex %s : classes=%d r8_sources=%d root(<=5c)=%d"
                    % (x["file"], x["classes"], x["sources_r8"], x["root_classes"]))
            if x["xor_strings"]:
                log.raw("  [DECODED XOR STRINGS]")
                for xr in x["xor_strings"][:20]:
                    log.raw("    %s  %s^%s = '%s'"
                            % (xr["class"], xr["cipher"], xr["key"], xr["decoded"][:80]))
                if len(x["xor_strings"]) > 20:
                    log.raw("    ... %d more" % (len(x["xor_strings"]) - 20))
            if x["integrity_gates"]:
                log.raw("  [INTEGRITY GATES (SHA-256 CreditGuard)]")
                for g in x["integrity_gates"][:15]:
                    log.raw("    %s.%s -> %s sha256=%s"
                            % (g["class"], g["method"], g["ret"],
                               ",".join(g["sha256_hex_constants"])))
                    for h in g["hints"]:
                        log.raw("        hint: %r" % h)
                if len(x["integrity_gates"]) > 15:
                    log.raw("    ... %d more" % (len(x["integrity_gates"]) - 15))

# --------------------------------------------------------------------------
# smali tooling discovery
# --------------------------------------------------------------------------

def find_java():
    for c in ("java",):
        p = shutil.which(c)
        if p:
            return p
    exe = "java.exe" if platform.system() == "Windows" else "java"
    for root in ("C:\\Program Files\\Java", "C:\\Program Files\\Microsoft",
                 os.path.expanduser("~"), "/usr/lib/jvm", "/data/data/com.termux/files/usr",):
        if os.path.isdir(root):
            for dp, dn, fns in os.walk(root):
                for fn in fns:
                    if fn.lower() == exe.lower():
                        return os.path.join(dp, fn)
                # limit walk depth
                if dp.count(os.sep) - root.count(os.sep) > 4:
                    pass
    return None

def find_jar(exe_hint):
    """search cwd, ./tools, temp for a jar matching hint."""
    for cand in ("%s.jar" % exe_hint, "smali-2.5.2.jar", "baksmali-2.5.2.jar"):
        for base in (".", os.path.join("tools"), tempfile.gettempdir(),
                     os.path.dirname(os.path.abspath(__file__))):
            p = os.path.join(base, cand)
            if os.path.exists(p):
                return p
    return None

def download(url, dest, timeout=120):
    if sys.version_info >= (3, 8):
        import urllib.request
        log.info("downloading %s" % url)
        urllib.request.urlretrieve(url, dest)
        return True
    return False

def run(cmd):
    if VERBOSE:
        log.info("exec: %s" % " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True)

# --------------------------------------------------------------------------
# deob pipeline
# --------------------------------------------------------------------------

def need_java(flag_java, flag_bs, flag_sm):
    java = flag_java or find_java()
    if not java:
        log.err("Java not found. On Termux: pkg install openjdk-17 ; apt-get install openjdk-17 -y")
        log.err("Then place smali.jar & baksmali.jar in ./tools or pass --baksmali/--smali.")
        raise SystemExit(2)
    res = _bundle_resources()
    bs = flag_bs or find_jar("baksmali") or res.get("baksmali.jar")
    sm = flag_sm or find_jar("smali") or res.get("smali.jar")
    if not bs or not sm:
        log.warn("baksmali/smali jars missing - attempt download (needs network).")
        for name, url, out in (
            ("baksmali", "https://github.com/google/smali/releases/download/v2.5.2/baksmali-2.5.2.jar", bs),
            ("smali", "https://github.com/google/smali/releases/download/v2.5.2/smali-2.5.2.jar", sm),
        ):
            if not out:
                dest = os.path.join("tools", "%s.jar" % name)
                os.makedirs("tools", exist_ok=True)
                if download(url, dest):
                    log.ok("downloaded %s -> %s" % (name, dest))
                    if name == "baksmali":
                        bs = dest
                    else:
                        sm = dest
    if not bs:
        log.err("baksmali.jar not available. Re-run with network, or pass --baksmali.")
        raise SystemExit(2)
    if not sm:
        log.err("smali.jar not available. Re-run with network, or pass --smali.")
        raise SystemExit(2)
    return java, bs, sm

def cmd_deob(args):
    java, bs, sm = need_java(args.java, args.baksmali, args.smali)
    apk = args.apk
    if not os.path.exists(apk):
        log.err("APK not found: %s" % apk)
        raise SystemExit(2)
    base = os.path.basename(apk)
    if not args.out:
        args.out = os.path.join(os.path.dirname(os.path.abspath(apk)), "deobfuscated")
    os.makedirs(args.out, exist_ok=True)
    work = os.path.join(args.out, "work")
    os.makedirs(work, exist_ok=True)
    smali_root = os.path.join(work, "smali_root")
    os.makedirs(smali_root, exist_ok=True)

    # -- extract + disassemble -----------------------------------------
    z = zipfile.ZipFile(apk)
    dex_names = sorted({z for z in z.namelist() if re.match(r"^classes\d*\.dex$", z)} or
                       [z for z in z.namelist() if re.match(r"^classes\d*\.dex$", z)])
    dex_paths = []
    for idx, name in enumerate(dex_names):
        task = Task("Disassembling %s" % name)
        data = z.read(name)
        p = os.path.join(work, name)
        with open(p, "wb") as f:
            f.write(data)
        out = os.path.join(smali_root, "smali" if idx == 0 else "smali_classes%d" % (idx + 1))
        r = run([java, "-jar", bs, "d", p, "-o", out])
        if r.returncode != 0:
            task.fail("baksmali error")
            log.err(r.stderr[-2000:])
            raise SystemExit(3)
        task.ok("%s -> %d smali" % (name, len(_walk_smali(out))))
        dex_paths.append((name, p))
    z.close()

    smali_files = _all_smali(smali_root)
    if not smali_files:
        log.err("no smali files generated")
        raise SystemExit(3)

    # -- analyze + deobfuscate -----------------------------------------
    markup = {"class_map": {}, "strings": [], "gates": [], "renamed": []}

    # 1) find XOR lazy-provider classes in smali and inline-decoded strings
    if args.decode_strings or args.auto_map:
        task = Task("Scanning XOR string pools")
        decoded = decode_smali_xor(smali_files)
        markup["strings"] = decoded
        task.ok("%d strings recovered" % len(decoded))
        if args.decode_strings:
            rewritten = inline_const_strings(smali_files, decoded)
            log.ok("inlined %d xor constants as const-string" % len(rewritten))

    # 2) class rename (auto + user map)
    if args.auto_map:
        task = Task("Building semantic map")
        auto = auto_semantic_map(smali_files, markup["strings"])
        markup["class_map"].update(auto)
        task.ok("%d classes detected" % len(auto))
    if args.rename_map:
        with io.open(args.rename_map, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                o, _, n = line.partition("=")
                markup["class_map"][o.strip()] = n.strip()

    task = Task("Renaming classes")
    applied = apply_rename(smali_files, markup["class_map"])
    markup["renamed"] = applied
    task.ok("%d classes renamed" % len(applied))

    # file paths may have moved during rename -> refresh list
    smali_files = _all_smali(smali_root)

    # 3) neutralize integrity gates
    if args.neutralize:
        task = Task("Neutralizing integrity gates")
        gates = neutralize_gates(smali_files)
        markup["gates"] = gates
        task.ok("%d gates neutralized" % len(gates))

    # 4) reassemble
    out_apk = os.path.join(args.out, "deobfuscated-" + safe_name(base))
    new_dex_paths = []
    for idx, (name, p) in enumerate(dex_paths):
        task = Task("Reassembling %s" % name)
        srcdir = os.path.join(smali_root,
                              "smali" if idx == 0 else "smali_classes%d" % (idx + 1))
        outdex = os.path.join(work, "out_" + name)
        r = run([java, "-jar", sm, "a", srcdir, "-o", outdex])
        if r.returncode != 0:
            task.fail("smali error")
            log.err(r.stderr[-2000:])
            raise SystemExit(4)
        task.ok("%s -> %s" % (name, os.path.basename(outdex)))
        new_dex_paths.append((name, outdex))

    task = Task("Rebuilding APK")
    rebuild_apk(apk, new_dex_paths, out_apk, args.keep_signature)
    task.ok(os.path.basename(out_apk))

    if args.sign:
        task = Task("Signing APK")
        ok_sign = sign_apk(out_apk, args)
        task.ok("signed v2/v3" if ok_sign else "NOT signed")

    # persist markup report
    with io.open(os.path.join(args.out, "deobfuscation_report.json"), "w",
                 encoding="utf-8") as f:
        json.dump(markup, f, indent=2, ensure_ascii=False)
    log.ok("DONE -> %s" % out_apk)
    log.ok("report -> %s" % os.path.join(args.out, "deobfuscation_report.json"))

# --------------------------------------------------------------------------
# smali-level helpers
# --------------------------------------------------------------------------

def parse_smali_class(path):
    with io.open(path, encoding="utf-8", errors="replace") as f:
        head = f.readline()
    m = re.match(r"\.class .*? (L[^;]+);", head)
    return m.group(1) if m else None

def decode_smali_xor(files):
    """Find classes with [I static arrays + a method doing cyclic XOR,
    and evaluate the method to plain strings."""
    results = []
    for path in files:
        with io.open(path, encoding="utf-8", errors="replace") as f:
            txt = f.read()
        arrays = {}
        m = re.search(r"\.class .*? (L[^;]+);", txt)
        cls = m.group(1) if m else "?"
        # collect static int arrays
        cur_method = None
        # two passes: parse arrays from <clinit> fill-array-data
        cl = re.search(r"\.method static constructor <clinit>\(\)V(.*?)\.end method",
                       txt, re.S)
        if cl:
            body = cl.group(1)
            # pair each fill-array-data with the next sput-object using the same
            # register (registers are reused sequentially for consecutive arrays)
            fills = []
            for fm in re.finditer(
                    r"fill-array-data v(\d+), :array_(\w+)", body):
                fills.append((fm.start(), "v" + fm.group(1), fm.group(2)))
            sputs = []
            for sm_ in re.finditer(r"sput-object v(\d+), ((?:L[^;]+;|\w+);->[^:]+):\[I", body):
                sputs.append((sm_.start(), "v" + sm_.group(1), sm_.group(2)))
            for fi, (fpos, freg, flabel) in enumerate(fills):
                sp = next((s for s in sputs if s[0] > fpos and s[1] == freg), None)
                if not sp:
                    continue
                data_match = re.search(
                    r":array_%s\s*\.array-data 4(.*?)\.end array-data" % flabel,
                    body, re.S)
                if not data_match:
                    continue
                data = [int(x.strip(), 16)
                        for x in re.findall(r"0x[0-9a-fA-F]+", data_match.group(1))]
                arrays[sp[2]] = data
        # decode any method calling a cyclic-xor pattern using those arrays
        for dm in re.finditer(
                r"\.method public static ([\w]+)\((\[I\[I)\)Ljava/lang/String;\s(.*?)\.end method",
                txt, re.S):
            name = dm.group(1)
            body = dm.group(3)
            # find two sget-object array refs
            refs = re.findall(r"sget-object v\d+, (L[^;]+;\-\>[a-z]+):\[I", body)
            refs = [r for r in refs if r in arrays]
            if len(refs) >= 1:
                # pattern decode: cipher ^ key where key is another field of same class,
                # or key param. Try all pairs.
                for f1 in refs:
                    for f2 in refs:
                        if f1 != f2:
                            s = decode_xor(arrays[f1], arrays[f2])
                            if printable(s):
                                results.append({
                                    "class": cls, "method": name,
                                    "cipher": f1.rsplit("->", 1)[-1],
                                    "key": f2.rsplit("->", 1)[-1],
                                    "decoded": s})
        # generic: any method returning String with rem-int & xor-int/2addr & arrays
        # fallback: pairwise XOR of every clinit [I field (report only, never inline)
        for f1name, v1 in arrays.items():
            for f2name, v2 in arrays.items():
                if f1name == f2name:
                    continue
                if not v1 or not v2:
                    continue
                s = decode_xor(v1, v2)
                if len(s) < 2 or not printable(s, min_ratio=0.7):
                    continue
                results.append({
                    "class": cls, "method": "",   # "" -> not inlineable
                    "cipher": f1name.rsplit("->", 1)[-1],
                    "key": f2name.rsplit("->", 1)[-1],
                    "decoded": s})
        cleaned = set()
        uniq = []
        for r in results:
            k = (r["class"], r["decoded"])
            if k not in cleaned:
                cleaned.add(k)
                uniq.append(r)
        results = uniq
    return results

def inline_const_strings(files, decoded):
    """Rewrite the XOR decrypt method bodies of the supplier classes:
    replace the whole body with return const-string <decoded>."""
    by_class = {}
    for d in decoded:
        by_class.setdefault(d["class"], []).append(d)
    written = []
    for path in files:
        with io.open(path, encoding="utf-8", errors="replace") as f:
            txt = f.read()
        m = re.search(r"\.class .*? (L[^;]+);", txt)
        if not m:
            continue
        cls = m.group(1)
        if cls not in by_class:
            continue
        changed = 0
        for d in by_class[cls]:
            old = d["method"]
            if not old:  # fallback decodes are report-only
                continue
            # replace body of `public/private static X([I[I)Ljava/lang/String;`
            pat = re.compile(
                r"(\.method (?:public|private|protected) static %s\(\[I\[I\)Ljava/lang/String;\s)"
                r".*?\.end method" % re.escape(old), re.S)
            newbody = (".line 1\n    const-string v0, %s\n    return-object v0\n"
                       ".end method" % json.dumps(d["decoded"]))
            txt2 = pat.sub(lambda mm: mm.group(1) + newbody, txt, count=1)
            if txt2 != txt:
                txt = txt2
                changed += 1
        if changed:
            with io.open(path, "w", encoding="utf-8") as f:
                f.write(txt)
            written.append(cls)
    return written

def auto_semantic_map(files, decoded):
    """Heuristic name assignment for classes that carry integrity/credit/session roles."""
    MAP = {}   # old fqn -> new fqn
    by_cls = {}
    for d in decoded:
        by_cls.setdefault(d["class"], []).append(d)
    for path in files:
        with io.open(path, encoding="utf-8", errors="replace") as f:
            txt = f.read()
        m = re.search(r"\.class .*? (L[^;]+);", txt)
        if not m:
            continue
        cls = m.group(1)
        low = txt.lower()
        base = cls.replace("/", ".").lstrip("L")
        new = None
        if re.search(r'const-string .*"integrity', low) and re.search(r'"sha-256"', low):
            new = "com.mcpanel.security.AppIntegrity"
        elif re.search(r'"integrity check failed"', low):
            new = "com.mcpanel.service.IntegrityGuard"
        elif re.search(r'"this build looks modified"', low):
            new = "com.mcpanel.auth.ModifiedBuildGate"
        elif re.search(r'"android_id"', low) and re.search(r'"enter your access key"', low):
            new = "com.mcpanel.auth.AccessKeyManager"
        elif re.search(r'"developed by"', low) and re.search(r'"sha-256"', low):
            new = "com.mcpanel.security.CreditGuard"
        elif re.search(r'"securityresult\(passed=', low):
            new = "com.mcpanel.security.SecurityResult"
        elif re.search(r'\.implements Ljava/lang/Runnable;', low) and \
             ('floatingmenuservice' in cls.lower() or '(Lcom/mcpanel/service/FloatingMenuService;I)V' in low):
            new = "com.mcpanel.service.ServiceActionRunnable"
        # avoid collision; only map if new not already used
        if new and new not in MAP.values():
            MAP[cls] = new
    return MAP

def apply_rename(files, class_map):
    if not class_map:
        return []
    # normalize: accept keys like "Ljt;" / "jt" / "Ljt; ;" -> build token pairs
    pairs = []
    seen = set()
    for o, n in class_map.items():
        if o == n:
            continue
        otok = o if o.startswith("L") and o.endswith(";") else "L" + o.strip("L;") + ";"
        ntok = "L" + n.replace(".", "/").strip(";") + ";"
        if otok == ntok:
            continue
        pairs.append((otok, ntok))
    if not pairs:
        return []
    # locate defining file for each old token BEFORE rewriting text
    old_file = {}
    for path in files:
        with io.open(path, encoding="utf-8", errors="replace") as f:
            head = f.readline()
        for ott, ntt in pairs:
            if ott in head and ott not in old_file:
                old_file[ott] = path
        if len(old_file) == len(pairs):
            break
    # rewrite occurrences
    applied = []
    for path in files:
        with io.open(path, encoding="utf-8", errors="replace") as f:
            txt = f.read()
        orig = txt
        for ott, ntt in pairs:
            txt = txt.replace(ott, ntt)
        if txt != orig:
            with io.open(path, "w", encoding="utf-8") as f:
                f.write(txt)
    # rename files for mapped classes
    for ott, ntt in pairs:
        path = old_file.get(ott)
        if not path:
            continue
        nd = os.path.join(os.path.dirname(path), ntt.strip("L;") + ".smali")
        os.makedirs(os.path.dirname(nd), exist_ok=True)
        if os.path.abspath(nd) != os.path.abspath(path):
            shutil.move(path, nd)
        applied.append("%s -> %s" % (ott, ntt))
    return applied

# --------------------------------------------------------------------------
# integrity gate neutralization (smali-level)
# --------------------------------------------------------------------------

def neutralize_gates(files):
    """Neutralize anti-tamper gates: rewrite the gate method to always PASS.

    Detect: methods whose body references an anti-tamper string (integrity /
    modified-build / uninstall). Then either
      - return type is Boolean        -> const/4 0x1 (true)
      - return type is a Result class -> new Result("", true) using the
        (Ljava/lang/String;Z)V constructor seen in the same body.
    """
    ANTITAMPER_IDX = re.compile(r"integrity|modified build|looks modified|official apk|"
                      r"uninstall and download|tamper|check failed",
                      re.IGNORECASE)
    fixed = []
    for path in files:
        with io.open(path, encoding="utf-8", errors="replace") as f:
            txt = f.read()
        m = re.search(r"\.class .*? (L[^;]+);", txt)
        if not m:
            continue
        cls = m.group(1)
        chunks = re.split(r"(?=\.method )", txt)
        changed = False
        for ch in chunks:
            if not ch.startswith(".method "):
                continue
            head = ch.split("\n", 1)[0]
            hm = re.match(r"\.method ((\w+\s)*)([A-Za-z_$][\w$]*)(\([^)]*\))(L[^;]+;)?", head)
            if not hm:
                continue
            if ANTITAMPER_IDX.search(ch) is None:
                continue
            rettype = hm.group(5)
            if rettype is None:  # primitive return type -> not patchable w/o care
                continue
            if rettype == "Z":
                stub = (".registers 1\n"
                        "    const/4 v0, 0x1\n"
                        "    return v0\n"
                        ".end method")
            else:
                ctor = re.search(r"-><init>\(Ljava/lang/String;Z\)V", ch)
                if not ctor:
                    continue
                stub = (".registers 3\n"
                        "    const-string v0, \"\"\n"
                        "    const/4 v1, 0x1\n"
                        "    new-instance v2, %s\n"
                        "    invoke-direct {v2, v0, v1}, %s-><init>(Ljava/lang/String;Z)V\n"
                        "    return-object v2\n"
                        ".end method" % (rettype, rettype))
            end = ch.find(".end method")
            if end < 0:
                continue
            txt = txt.replace(ch, head + "\n" + stub + "\n")
            changed = True
            fixed.append((cls, hm.group(3), rettype))
        if changed:
            with io.open(path, "w", encoding="utf-8") as f:
                f.write(txt)
    return sorted(set(fixed))

# --------------------------------------------------------------------------
# rebuild + sign
# --------------------------------------------------------------------------

def _write_aligned(zo, name, data, compress_type, align=4):
    """Write an entry padded so its data starts on an `align` boundary
    (mirrors zipalign, so no native zipalign binary is needed)."""
    zi = zipfile.ZipInfo(name)
    zi.compress_type = compress_type
    before = zo.fp.tell()
    pad = (align - ((before + 30 + len(name)) % align)) % align
    zi.extra = b"\x00" * pad
    zo.writestr(zi, data)

def rebuild_apk(apk, new_dex_pairs, out_apk, keep_sig=False):
    z = zipfile.ZipFile(apk)
    names = z.namelist()
    newmap = dict(new_dex_pairs)
    with zipfile.ZipFile(out_apk, "w") as zo:
        for n in names:
            if n in newmap:
                with io.open(newmap[n], "rb") as f:
                    data = f.read()
                _write_aligned(zo, n, data, zipfile.ZIP_DEFLATED, 4)
                continue
            if not keep_sig and re.match(r"^META-INF/.*\.(SF|RSA|DSA|EC)$", n):
                continue
            if n == "META-INF/MANIFEST.MF" and not keep_sig:
                continue
            data = z.read(n)
            ct = z.getinfo(n).compress_type
            align = 4096 if (n.startswith("lib/") and ct == zipfile.ZIP_STORED) else 4
            _write_aligned(zo, n, data, ct, align)
    z.close()

def _apksigner_cmd(args, res):
    tool = args.apksigner or shutil.which("apksigner")
    if tool:
        return [tool]
    aj = res.get("apksigner.jar")
    java = find_java()
    if aj and java:
        return [java, "-jar", aj]
    return None

def sign_apk(apk_path, args):
    res = _bundle_resources()
    ks = args.ks or res.get("mdeob.keystore") or res.get("signing.keystore")
    if getattr(args, "ks_alias", None):
        alias = args.ks_alias
    elif ks and not args.ks and os.path.basename(ks) == "mdeob.keystore":
        alias = "mdeob"
    else:
        alias = "android"
    base = _apksigner_cmd(args, res)
    if not base:
        log.err("apksigner not found (install it, pass --apksigner, or use the bundled build).")
        log.err("APK built but NOT signed: %s", apk_path)
        return False
    cmd = base + ["sign"]
    if ks:
        cmd += ["--ks", ks]
        cmd += ["--ks-key-alias", alias]
        if args.ks_pass:
            cmd += ["--ks-pass", "pass:%s" % args.ks_pass]
        elif os.path.basename(ks) == "mdeob.keystore":
            cmd += ["--ks-pass", "pass:mdeob123"]
        if args.key_pass:
            cmd += ["--key-pass", "pass:%s" % args.key_pass]
        elif os.path.basename(ks) == "mdeob.keystore":
            cmd += ["--key-pass", "pass:mdeob123"]
    cmd += ["--out", apk_path + ".signed", apk_path]
    r = run(cmd)
    if r.returncode == 0 and os.path.exists(apk_path + ".signed"):
        shutil.move(apk_path + ".signed", apk_path)
        return True
    log.err("apksigner failed:\n%s", r.stderr[-1500:])
    return False

def _walk_smali(d):
    out = []
    for dp, dn, fns in os.walk(d):
        for fn in fns:
            if fn.endswith(".smali"):
                out.append(os.path.join(dp, fn))
    return out

def _all_smali(smali_root):
    return _walk_smali(smali_root)

def cmd_rebuild(args):
    apk = args.apk
    pairs = []
    for dex in args.dex:
        n = os.path.basename(dex)
        pairs.append((n, dex))
    if not args.out:
        args.out = os.path.join(os.path.dirname(os.path.abspath(apk)),
                                "deobfuscated", "rebuild-" + safe_name(os.path.basename(apk)))
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    task = Task("Rebuilding APK")
    rebuild_apk(apk, pairs, args.out, args.keep_signature)
    task.ok(os.path.basename(args.out))
    if args.sign:
        task = Task("Signing APK")
        ok_sign = sign_apk(args.out, args)
        task.ok("signed v2/v3" if ok_sign else "NOT signed")

def cmd_sign(args):
    task = Task("Signing APK")
    ok_sign = sign_apk(args.apk, args)
    task.ok("signed v2/v3" if ok_sign else "NOT signed")

# --------------------------------------------------------------------------

BANNER = (
    "+------------------------------------------------------------+\n"
    "|  MCLOCK DE-OBFUSCATOR            v%s                    |\n"
    "|  android apk: analyze / deob / rebuild / sign              |\n"
    "+------------------------------------------------------------+"
)

def main():
    # convenience: `mdeob some.apk [flags]` == `mdeob deob some.apk [flags]`
    argv = list(sys.argv[1:])
    if argv and argv[0] not in ("analyze", "deob", "rebuild", "sign", "-h", "--help"):
        if os.path.isfile(argv[0]) and zipfile.is_zipfile(argv[0]):
            argv.insert(0, "deob")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="store_true", help="show tool commands")

    p = argparse.ArgumentParser(prog="mdeob", description=(NAME + " v" + VERSION +
                                                           " | android apk toolkit"))
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("analyze", parents=[common],
                        help="pure-python dex scan (no java)")
    pa.add_argument("apk", nargs="+")
    pa.add_argument("--json", metavar="FILE")
    pa.add_argument("--scan-methods", action="store_true")
    pa.set_defaults(fn=cmd_analyze)

    pd = sub.add_parser("deob", parents=[common],
                        help="full pipeline: decode, rename, neutralize, rebuild, sign (all ON by default)")
    pd.add_argument("apk")
    pd.add_argument("--out", default=None,
                    help="output dir (default: <apk dir>/deobfuscated/)")
    pd.add_argument("--java", default=None)
    pd.add_argument("--baksmali", dest="baksmali", default=None)
    pd.add_argument("--smali", default=None)
    pd.add_argument("--no-decode-strings", dest="decode_strings", action="store_false",
                    help="skip XOR string recovery/inlining")
    pd.add_argument("--no-auto-map", dest="auto_map", action="store_false",
                    help="skip semantic class renaming")
    pd.add_argument("--rename-map", metavar="FILE",
                    help="file with OLD=NEW lines")
    pd.add_argument("--no-neutralize", dest="neutralize", action="store_false",
                    help="skip integrity-gate neutralization")
    pd.add_argument("--keep-signature", action="store_true")
    pd.add_argument("--no-sign", dest="sign", action="store_false",
                    help="do not sign (signed by default, bundled keystore)")
    pd.add_argument("--ks", default=None)
    pd.add_argument("--ks-alias", dest="ks_alias", default=None,
                    help="keystore alias (default: mdeob)")
    pd.add_argument("--ks-pass", default=None)
    pd.add_argument("--key-pass", default=None)
    pd.add_argument("--apksigner", default=None)
    pd.set_defaults(decode_strings=True, auto_map=True, neutralize=True, sign=True)
    pd.set_defaults(fn=cmd_deob)

    pr = sub.add_parser("rebuild", parents=[common],
                        help="rebuild APK from replaced dex(s)")
    pr.add_argument("apk")
    pr.add_argument("dex", nargs="+", help="replacement dex files (classes.dex, ...)")
    pr.add_argument("--out", default=None)
    pr.add_argument("--keep-signature", action="store_true")
    pr.add_argument("--sign", action="store_true")
    pr.add_argument("--ks", default=None)
    pr.add_argument("--ks-alias", dest="ks_alias", default="android")
    pr.add_argument("--ks-pass", default=None)
    pr.add_argument("--key-pass", default=None)
    pr.add_argument("--apksigner", default=None)
    pr.set_defaults(fn=cmd_rebuild)

    ps = sub.add_parser("sign", parents=[common], help="sign an APK")
    ps.add_argument("apk")
    ps.add_argument("--ks", default=None)
    ps.add_argument("--ks-alias", dest="ks_alias", default="android")
    ps.add_argument("--ks-pass", default=None)
    ps.add_argument("--key-pass", default=None)
    ps.add_argument("--apksigner", default=None)
    ps.set_defaults(fn=cmd_sign)

    args = p.parse_args(argv)
    if args.verbose:
        global VERBOSE
        VERBOSE = True
    if _is_tty():
        print(_c("36", BANNER % VERSION))
    try:
        args.fn(args)
    except KeyboardInterrupt:
        log.err("interrupted.")
        raise SystemExit(130)
    except ValueError as e:
        log.err(str(e))
        raise SystemExit(1)

if __name__ == "__main__":
    main()