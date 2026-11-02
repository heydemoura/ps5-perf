#!/usr/bin/env python3
"""ps5perf - host side client for the ps5-perf payload.

Talks to the payload over TCP (default port 9077) and turns the recorded
samples into the formats the Linux perf ecosystem understands:

  ps5perf.py -H 192.168.0.190 ps
  ps5perf.py -H 192.168.0.190 stat -p eboot.bin -d 5 --per-thread
  ps5perf.py -H 192.168.0.190 top -p eboot.bin
  ps5perf.py -H 192.168.0.190 record -p eboot.bin -g -F 499 -d 10 -o game
      -> game.ps5perf        raw recording (re-processable offline)
         game.perf-script    `perf script` text (speedscope, Firefox profiler,
                             FlameGraph's stackcollapse-perf.pl, ...)
         game.folded         collapsed stacks (flamegraph.pl / inferno)
         game.svg            interactive flame graph
  ps5perf.py report -i game.ps5perf [--sort comm,dso,sym] [--children] [-g]
  ps5perf.py script -i game.ps5perf

Sony NIDs (the hashed export names of system modules) are resolved to real
names using the symbol names found in the PS5 payload SDK's stub libraries
($PS5_PAYLOAD_SDK/target/lib/*.so). Additional symbols can be supplied with
--symfs DIR (unstripped ELFs named like the module, e.g. DIR/eboot.bin).
"""

import argparse
import base64
import collections
import hashlib
import html
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

DEFAULT_PORT = 9077
NID_SALT = bytes.fromhex("518d64a635ded8c1e6b039b1c3e55230")

# --------------------------------------------------------------- NIDs -----


def nid_encode(name):
    d = hashlib.sha1(name.encode() + NID_SALT).digest()
    v = struct.unpack("<Q", d[:8])[0]
    return base64.b64encode(struct.pack(">Q", v)).decode().replace("/", "-")[:11]


def _nm_names(path):
    nm = shutil.which("llvm-nm") or shutil.which("nm")
    if not nm:
        return []
    try:
        out = subprocess.run([nm, "-D", "--defined-only", path], capture_output=True,
                             text=True, timeout=60).stdout
    except Exception:
        return []
    return [l.split()[-1] for l in out.splitlines() if len(l.split()) >= 3]


def load_nid_db(extra=None):
    """NID -> name map, cached in ~/.cache/ps5perf/nids.json."""
    cache = os.path.join(os.path.expanduser("~"), ".cache", "ps5perf", "nids.json")
    db = {}
    if os.path.exists(cache):
        try:
            with open(cache) as f:
                db = json.load(f)
        except Exception:
            db = {}
    if not db:
        names = set()
        sdk = os.environ.get("PS5_PAYLOAD_SDK")
        cands = [sdk] if sdk else []
        cands += [os.path.expanduser("~/ps5/ps5-payload-sdk"), "/opt/ps5-payload-sdk"]
        for root in cands:
            libdir = os.path.join(root or "", "target", "lib")
            if os.path.isdir(libdir):
                for fn in os.listdir(libdir):
                    if fn.endswith(".so"):
                        names.update(_nm_names(os.path.join(libdir, fn)))
                break
        db = {nid_encode(n): n for n in names}
        if db:
            os.makedirs(os.path.dirname(cache), exist_ok=True)
            with open(cache, "w") as f:
                json.dump(db, f)
    if extra:
        with open(extra) as f:
            for line in f:
                n = line.strip()
                if n and not n.startswith("#"):
                    db[nid_encode(n)] = n
    return db

# ------------------------------------------------------------ network -----


class Conn:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=15)
        self.s.settimeout(None)
        self.f = self.s.makefile("rb")
        self.read_until_end()                      # banner

    def send(self, line):
        self.s.sendall((line.strip() + "\n").encode())

    def stop(self):
        try:
            self.s.sendall(b"\n")
        except OSError:
            pass

    def lines(self):
        """yield decoded lines of one command's output, stop at #END"""
        for raw in self.f:
            line = raw.decode("utf-8", "replace")
            if line.startswith("#END rc="):
                self.rc = int(line.split("=", 1)[1])
                return
            yield line
        self.rc = -1

    def read_until_end(self):
        return "".join(self.lines())


def run_with_interrupt(conn, cmd, consume):
    """send cmd; Ctrl-C asks the payload to stop instead of killing us"""
    stopped = [False]

    def on_sigint(sig, frm):
        if not stopped[0]:
            stopped[0] = True
            sys.stderr.write("\n[ps5perf] stopping...\n")
            conn.stop()

    old = signal.signal(signal.SIGINT, on_sigint)
    try:
        conn.send(cmd)
        consume(conn.lines())
    finally:
        signal.signal(signal.SIGINT, old)
    return conn.rc

# ---------------------------------------------------------- recording -----


class Module:
    __slots__ = ("idx", "base", "text_end", "map_end", "name", "path", "funcs", "starts")

    def __init__(self, idx, base, text_end, map_end, name, path):
        self.idx, self.base, self.text_end, self.map_end = idx, base, text_end, map_end
        self.name, self.path = name, path
        self.funcs = {}          # rel start -> (size, name)
        self.starts = None


class Recording:
    def __init__(self):
        self.header = {}
        self.trailer = {}
        self.mods = []
        self.threads = {}
        self.samples = []        # (time_ns, tid, cpu, weight_ns, [ips])

    def feed(self, line):
        if not line or line[0] == "#":
            return
        tag, _, rest = line.rstrip("\n").partition(" ")
        if tag == "S":
            p = rest.split(" ")
            ips = [int(x, 16) for x in p[4].split(",")] if len(p) > 4 and p[4] else []
            self.samples.append((int(p[0]), int(p[1]), int(p[2]), int(p[3]), ips))
        elif tag == "F":
            p = rest.split(" ", 3)
            m = self.mods[int(p[0])]
            m.funcs[int(p[1], 16)] = (int(p[2], 16), None if p[3] == "-" else p[3])
        elif tag == "T":
            tid, _, name = rest.partition(" ")
            self.threads[int(tid)] = name
        elif tag == "M":
            p = rest.split(" ", 5)
            self.mods.append(Module(int(p[0]), int(p[1], 16), int(p[2], 16), int(p[3], 16),
                                    p[4], p[5] if len(p) > 5 else "-"))
        elif tag == "H":
            self.header = dict(kv.split("=", 1) for kv in rest.split(" ") if "=" in kv)
        elif tag == "X":
            self.trailer = dict(kv.split("=", 1) for kv in rest.split(" ") if "=" in kv)
        elif line.startswith("error:"):
            raise RuntimeError(line.strip())

    @classmethod
    def load(cls, path):
        r = cls()
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                r.feed(line)
        return r

# --------------------------------------------------------- symbolizer -----


class Symbolizer:
    def __init__(self, rec, nids, symfs=None, symmap=None):
        self.rec = rec
        self.nids = nids
        self.mods = sorted(rec.mods, key=lambda m: m.base)
        self.bases = [m.base for m in self.mods]
        self.cache = {}
        self.symfs_syms = {}
        for m in self.mods:
            p = (symmap or {}).get(m.name)
            if not p and symfs and os.path.isfile(os.path.join(symfs, m.name)):
                p = os.path.join(symfs, m.name)
            if p:
                self.symfs_syms[m.idx] = self._elf_syms(p)
        for m in self.mods:
            m.starts = sorted(m.funcs)

    @staticmethod
    def _elf_syms(path):
        """(sorted starts, {rel: (size, name)}) from an unstripped ELF via nm"""
        nm = shutil.which("llvm-nm") or shutil.which("nm")
        if not nm:
            return None
        out = subprocess.run([nm, "-S", "--defined-only", "-C", path], capture_output=True,
                             text=True).stdout
        lowest = None
        syms = {}
        for l in out.splitlines():
            p = l.split(None, 3)
            if len(p) == 4 and p[2] in "tTwW":
                a, s = int(p[0], 16), int(p[1], 16)
                syms[a] = (s, p[3])
                lowest = a if lowest is None else min(lowest, a)
        # symbols are relative to the image's first load address
        try:
            ro = subprocess.run([shutil.which("llvm-readelf") or "readelf", "-lW", path],
                                capture_output=True, text=True).stdout
            loads = [int(l.split()[2], 16) for l in ro.splitlines() if l.strip().startswith("LOAD")]
            first = min(loads) if loads else 0
        except Exception:
            first = 0
        rel = {a - first: v for a, v in syms.items()}
        return sorted(rel), rel

    def module(self, addr):
        import bisect
        i = bisect.bisect_right(self.bases, addr) - 1
        if i >= 0 and addr < self.mods[i].map_end:
            return self.mods[i]
        return None

    def name(self, n):
        if n and len(n) == 11 and n in self.nids:
            return self.nids[n]
        return n

    def lookup(self, addr):
        """-> (symbol, offset, dso)"""
        hit = self.cache.get(addr)
        if hit:
            return hit
        import bisect
        m = self.module(addr)
        if not m:
            res = ("[unknown]", 0, "[unknown]")
        else:
            rel = addr - m.base
            res = None
            ss = self.symfs_syms.get(m.idx)
            if ss:
                starts, syms = ss
                i = bisect.bisect_right(starts, rel) - 1
                if i >= 0 and rel - starts[i] < max(syms[starts[i]][0], 1):
                    res = (syms[starts[i]][1], rel - starts[i], m.name)
            if not res:
                i = bisect.bisect_right(m.starts, rel) - 1
                if i >= 0 and rel - m.starts[i] < m.funcs[m.starts[i]][0]:
                    st = m.starts[i]
                    nm = self.name(m.funcs[st][1]) or "sub_%x" % st
                    res = (nm, rel - st, m.name)
                else:
                    res = ("%s+0x%x" % (m.name, rel), 0, m.name)
        self.cache[addr] = res
        return res

    def frame(self, ips, i):
        """symbolize frame i; return addresses are looked up at ip-1"""
        a = ips[i]
        sym, off, dso = self.lookup(a - 1 if i else a)
        return sym, (off + 1 if i and sym[0] != "[" and "+0x" not in sym else off), dso

# ------------------------------------------------------------ outputs -----


def write_perf_script(rec, sy, out):
    pid = rec.header.get("pid", "0")
    comm = rec.header.get("comm", "?")
    for t, tid, cpu, w, ips in rec.samples:
        tname = rec.threads.get(tid) or comm
        out.write("%s %s/%d [%03d] %d.%06d: %d cpu-clock:\n" %
                  (tname.replace(" ", "_"), pid, tid, cpu, t // 10**9, (t // 1000) % 10**6, w))
        for i in range(len(ips)):
            sym, off, dso = sy.frame(ips, i)
            if off:
                out.write("\t%16x %s+0x%x (%s)\n" % (ips[i], sym, off, dso))
            else:
                out.write("\t%16x %s (%s)\n" % (ips[i], sym, dso))
        out.write("\n")


def folded(rec, sy, per_thread=True):
    acc = collections.Counter()
    comm = rec.header.get("comm", "?")
    for t, tid, cpu, w, ips in rec.samples:
        frames = [sy.frame(ips, i)[0] for i in range(len(ips))]
        frames.reverse()
        if per_thread:
            frames.insert(0, (rec.threads.get(tid) or comm) + "-%d" % tid)
        acc[";".join(f.replace(";", ":") for f in frames)] += max(w // 1000, 1)
    return acc


def flamegraph_svg(stacks, title, out, width=1600):
    """minimal self-contained flame graph (icicle-free, root at bottom)"""
    root = {"n": "all", "v": 0, "c": {}}
    for st, v in stacks.items():
        root["v"] += v
        node = root
        for fr in st.split(";"):
            node = node["c"].setdefault(fr, {"n": fr, "v": 0, "c": {}})
            node["v"] += v
    depth = [0]

    def maxd(n, d):
        depth[0] = max(depth[0], d)
        for c in n["c"].values():
            maxd(c, d + 1)
    maxd(root, 0)
    fh, pad = 16, 30
    height = (depth[0] + 1) * fh + pad * 2 + 20
    total = root["v"] or 1
    rects = []

    def color(name):
        h = int(hashlib.md5(name.encode()).hexdigest()[:6], 16)
        if name.startswith("sub_") or "+0x" in name:
            return "rgb(%d,%d,%d)" % (200 + h % 55, 120 + (h >> 8) % 80, 40 + (h >> 16) % 40)
        return "rgb(%d,%d,%d)" % (220 + h % 35, 80 + (h >> 8) % 120, 30 + (h >> 16) % 50)

    def walk(n, x, d):
        w = n["v"] / total * (width - 20)
        if w >= 0.3:
            y = height - pad - (d + 1) * fh
            pct = 100.0 * n["v"] / total
            label = html.escape(n["n"])
            txt = ""
            if w > 30:
                chars = int(w / 7)
                t = n["n"] if len(n["n"]) <= chars else n["n"][:max(chars - 2, 0)] + ".."
                txt = '<text x="%.1f" y="%.1f">%s</text>' % (x + 3, y + 11.5, html.escape(t))
            rects.append('<g><title>%s (%.2f%%, %d)</title><rect x="%.1f" y="%.1f" width="%.1f" '
                         'height="%d" fill="%s" rx="2"/>%s</g>' %
                         (label, pct, n["v"], x, y, w, fh - 1, color(n["n"]), txt))
        cx = x
        for c in sorted(n["c"].values(), key=lambda c: c["n"]):
            walk(c, cx, d + 1)
            cx += c["v"] / total * (width - 20)
    walk(root, 10, 0)
    out.write('<?xml version="1.0" standalone="no"?>\n'
              '<svg version="1.1" width="%d" height="%d" xmlns="http://www.w3.org/2000/svg">\n'
              '<style>text{font:12px Verdana,sans-serif;fill:#000;pointer-events:none}'
              'g:hover rect{stroke:#000;stroke-width:0.5}</style>\n'
              '<rect width="100%%" height="100%%" fill="#f8f8f0"/>\n'
              '<text x="%d" y="22" text-anchor="middle" style="font-size:17px">%s</text>\n'
              % (width, height, width // 2, html.escape(title)))
    out.write("\n".join(rects))
    out.write("\n</svg>\n")


def report(rec, sy, sort="comm,dso,sym", children=False, callers=False, limit=40, out=sys.stdout):
    keys = [k for k in sort.split(",") if k in ("comm", "tid", "dso", "sym")] or ["comm", "dso", "sym"]
    comm = rec.header.get("comm", "?")
    selfw, selfn = collections.Counter(), collections.Counter()
    childw = collections.Counter()
    chains = collections.defaultdict(collections.Counter)
    total = 0

    def key(tid, sym, dso):
        v = {"comm": rec.threads.get(tid) or comm, "tid": str(tid), "dso": dso, "sym": sym}
        return tuple(v[k] for k in keys)

    for t, tid, cpu, w, ips in rec.samples:
        if not ips:
            continue
        total += w
        sym, off, dso = sy.frame(ips, 0)
        k = key(tid, sym, dso)
        selfw[k] += w
        selfn[k] += 1
        if callers and len(ips) > 1:
            chains[k][tuple(sy.frame(ips, i)[0] for i in range(1, min(len(ips), 9)))] += w
        if children:
            seen = set()
            for i in range(len(ips)):
                s2, _, d2 = sy.frame(ips, i)
                k2 = key(tid, s2, d2)
                if k2 not in seen:
                    seen.add(k2)
                    childw[k2] += w
    total = total or 1
    el = float(rec.trailer.get("elapsed", "0") or 0)
    fw = rec.header.get("fw", "0")
    try:
        v = int(fw, 16)
        fw = "%x.%02x" % ((v >> 24) & 0xff, (v >> 16) & 0xff)
    except ValueError:
        pass
    out.write("# ps5-perf report: pid %s (%s), PS5 fw %s\n" % (rec.header.get("pid"), comm, fw))
    out.write("# Samples: %d  of event 'cpu-clock'  (sampling mode: %s, %s Hz)\n" %
              (len(rec.samples), rec.trailer.get("mode", "?").replace("_", " "),
               rec.header.get("freq")))
    out.write("# Event count (approx.): %d ns  (%.2f CPUs over %.2fs)\n" %
              (total, total / 1e9 / el if el else 0, el))
    out.write("# Target stopped avg %s us / max %s us per stop\n#\n" %
              (rec.trailer.get("stop_avg_us", "?"), rec.trailer.get("stop_max_us", "?")))
    order = sorted(childw if children else selfw, key=lambda k: -(childw if children else selfw)[k])
    names = {"comm": "Command", "tid": "Tid", "dso": "Shared Object", "sym": "Symbol"}
    widths = [max([len(names[k])] + [len(o[i]) for o in order[:limit]]) for i, k in enumerate(keys)]
    widths = [min(w, 60) for w in widths]
    hdr = "# %s %8s  " % ("Children      Self" if children else "Overhead", "Samples")
    out.write(hdr + "  ".join(names[k].ljust(w) for k, w in zip(keys, widths)) + "\n#\n")
    for k in order[:limit]:
        cols = "  ".join(("[.] " if keys[i] == "sym" else "") + k[i][:60].ljust(widths[i])
                         for i in range(len(keys)))
        if children:
            out.write("  %7.2f%%  %7.2f%% %8d  %s\n" % (100.0 * childw[k] / total,
                                                       100.0 * selfw[k] / total, selfn[k], cols))
        else:
            out.write("  %7.2f%% %8d  %s\n" % (100.0 * selfw[k] / total, selfn[k], cols))
        if callers and chains.get(k):
            tot = sum(chains[k].values())
            for ch, w in chains[k].most_common(3):
                out.write("            |--%5.2f%%-- %s\n" % (100.0 * w / tot, ch[0]))
                for f in ch[1:]:
                    out.write("            |           <- %s\n" % f)
            out.write("\n")
    out.write("\n")


def convert(rec, sy, prefix, quiet=False):
    files = []
    with open(prefix + ".perf-script", "w") as f:
        write_perf_script(rec, sy, f)
    files.append(prefix + ".perf-script")
    st = folded(rec, sy)
    with open(prefix + ".folded", "w") as f:
        for k, v in sorted(st.items()):
            f.write("%s %d\n" % (k, v))
    files.append(prefix + ".folded")
    with open(prefix + ".svg", "w") as f:
        flamegraph_svg(st, "ps5-perf: %s (pid %s) - cpu-clock, %d samples" %
                       (rec.header.get("comm"), rec.header.get("pid"), len(rec.samples)), f)
    files.append(prefix + ".svg")
    if not quiet:
        sys.stderr.write("[ps5perf] wrote %s\n" % ", ".join(files))

# ------------------------------------------------------------ commands ----


def cmd_record(args, rest):
    conn = Conn(args.host, args.port)
    prefix = args.output
    raw_path = prefix + ".ps5perf"
    rec = Recording()
    n = [0]
    t0 = time.time()

    with open(raw_path, "w") as raw:
        def consume(lines):
            for line in lines:
                raw.write(line)
                if line.startswith("S "):
                    n[0] += 1
                    if n[0] % 500 == 0:
                        sys.stderr.write("\r[ps5perf] %d samples, %.1fs" % (n[0], time.time() - t0))
                elif line.startswith("error"):
                    sys.stderr.write(line)
                rec.feed(line)
        sys.stderr.write("[ps5perf] recording (Ctrl-C to stop)...\n")
        rc = run_with_interrupt(conn, "record " + " ".join(rest), consume)
    sys.stderr.write("\r[ps5perf] %d samples captured into %s\n" % (len(rec.samples), raw_path))
    if rc != 0:
        return rc
    sy = Symbolizer(rec, load_nid_db(args.nid_names), args.symfs, args.symmap)
    convert(rec, sy, prefix)
    report(rec, sy, limit=args.lines)
    return 0


def cmd_offline(args, rest, what):
    if not args.input:
        sys.stderr.write("error: -i <file.ps5perf> required for offline %s\n" % what)
        return 2
    rec = Recording.load(args.input)
    sy = Symbolizer(rec, load_nid_db(args.nid_names), args.symfs, args.symmap)
    if what == "report":
        report(rec, sy, sort=args.sort, children=args.children, callers=args.callers,
               limit=args.lines)
    elif what == "script":
        write_perf_script(rec, sy, sys.stdout)
    elif what == "convert":
        convert(rec, sy, args.output or os.path.splitext(args.input)[0])
    return 0


def cmd_passthrough(args, cmdline):
    conn = Conn(args.host, args.port)
    is_top = cmdline.split()[0] == "top"
    frame = []

    def consume(lines):
        for line in lines:
            if is_top and sys.stdout.isatty():
                if line.startswith("#END-FRAME"):
                    sys.stdout.write("\x1b[H\x1b[2J" + "".join(frame))
                    sys.stdout.flush()
                    frame.clear()
                    continue
                frame.append(line)
                continue
            if line.startswith("#END-FRAME"):
                continue
            sys.stdout.write(line)
            sys.stdout.flush()
    try:
        rc = run_with_interrupt(conn, cmdline, consume)
        if frame:
            sys.stdout.write("".join(frame))
        sys.stdout.flush()
    except BrokenPipeError:
        # reader went away (e.g. `| head`): stop the remote command quietly
        conn.stop()
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
    return rc


def main():
    ap = argparse.ArgumentParser(
        description="host client for the ps5-perf PS5 payload", allow_abbrev=False,
        epilog="remote commands: ps threads maps list stat record script report top version "
               "help shutdown. Unknown options are passed to the payload.")
    ap.add_argument("-H", "--host", default=os.environ.get("PS5_HOST", "ps5"),
                    help="console address (default: $PS5_HOST or \"ps5\")")
    ap.add_argument("-P", "--port", type=int, default=int(os.environ.get("PS5PERF_PORT", DEFAULT_PORT)))
    ap.add_argument("-o", "--output", help="output prefix for record/convert (default perf)")
    ap.add_argument("-i", "--input", help="offline: .ps5perf recording to process")
    ap.add_argument("--symfs", help="directory with unstripped ELFs named like the modules")
    ap.add_argument("--sym", action="append", default=[], metavar="MODULE=ELF",
                    help="symbolize MODULE with an unstripped ELF, e.g. payload.elf=build/my.elf")
    ap.add_argument("--nid-names", help="extra symbol names (one per line) for NID resolution")
    ap.add_argument("--lines", type=int, default=40, help="report rows")
    ap.add_argument("command")
    args, rest = ap.parse_known_args()
    args.symmap = dict(s.split("=", 1) for s in args.sym if "=" in s)

    # offline-only report options
    args.sort, args.children, args.callers = "comm,dso,sym", False, False
    if args.input:
        r2 = []
        it = iter(rest)
        for a in it:
            if a in ("-s", "--sort"):
                args.sort = next(it)
            elif a == "--children":
                args.children = True
            elif a in ("-g", "--call-graph"):
                args.callers = True
            else:
                r2.append(a)
        rest = r2

    if args.command == "record":
        args.output = args.output or "perf"
        return cmd_record(args, rest)
    if args.input and args.command in ("report", "script", "convert"):
        return cmd_offline(args, rest, args.command)
    if args.command == "convert":
        sys.stderr.write("error: convert needs -i <file.ps5perf>\n")
        return 2
    return cmd_passthrough(args, " ".join([args.command] + rest))


if __name__ == "__main__":
    sys.exit(main() or 0)
