#!/usr/bin/env python3
# chaos_dll_runner_hardcoded.py
# Windows-only. Hardcoded config. No argparse.

import os, sys, struct, random, time, ctypes
import multiprocessing as mp
from pathlib import Path
import mmap

# ==== HARD-CODED CONFIG (your values) ========================================
ROOT_DIR             = r"C:\Windows"   # ⚠️ VERY risky. Prefer a safe test folder you control.
WORKERS              = 800                       # parallel child processes
TOTAL_DURATION_SEC   = 6000                    # total orchestrator runtime
CALLS_PER_CHILD      = 111                       # random calls per child
MAX_ARGS_PER_CALL    = 51                      # 0..N args
MAX_RANDOM_BUF_BYTES = 8192                     # max buffer size for pointer args
CHILD_TIMEOUT_SEC    = 121                     # kill/replace child after this many seconds
SCAN_LIMIT_DLLS      = 20000                    # (legacy cap; fast scanner uses TARGET_DLLS/time budget)
RNG_SEED             = None                     # set to an int for reproducible chaos, or None

# --- FAST SCANNING SETTINGS ---
RECURSIVE            = True                    # False = only top-level of ROOT_DIR (fastest)
TARGET_DLLS          = 3000                      # stop scanning once we have this many candidates
SCAN_TIME_BUDGET_SEC = 20.0                      # hard stop for scanning phase
MAX_EXPORTS_PER_DLL  = 640                       # at most N names per DLL (enough for chaos)
EXCLUDE_DIR_NAMES    = {
}
# Optional, but helps DLL dependency resolution: prepend each target DLL's dir to PATH in the child
PREPEND_DLL_DIR_TO_PATH = True
# ============================================================================

# --- minimal helpers (x64 PE parsing) ---
class PEError(Exception): pass
def _u16(b,o): return struct.unpack_from("<H", b, o)[0]
def _u32(b,o): return struct.unpack_from("<I", b, o)[0]

# fast header sniff (reads only a few KB)
def _quick_is_x64_and_has_exports(fp):
    """
    Read only headers to decide:
      - PE32+ (x64)
      - Has a non-zero export directory
    Returns (is_x64, export_rva, export_size, num_sections, opt_off, opt_size)
    """
    fp.seek(0, os.SEEK_SET)
    hdr = fp.read(4096)
    if len(hdr) < 0x100: return (False, 0, 0, 0, 0, 0)
    if hdr[:2] != b"MZ": return (False, 0, 0, 0, 0, 0)
    pe = _u32(hdr, 0x3C)
    if pe + 0xF8 > len(hdr):
        try:
            fp.seek(pe, os.SEEK_SET)
            hdr = fp.read(0x400)
        except Exception:
            return (False, 0, 0, 0, 0, 0)
        if len(hdr) < 0x108: return (False, 0, 0, 0, 0, 0)
        pe = 0
    if hdr[pe:pe+4] != b"PE\x00\x00": return (False, 0, 0, 0, 0, 0)
    fh    = pe + 4
    mach  = _u16(hdr, fh + 0x00)
    nsect = _u16(hdr, fh + 0x02)
    optsz = _u16(hdr, fh + 0x10)
    opt   = fh + 20
    if opt + 0x74 > len(hdr): return (False, 0, 0, 0, 0, 0)
    magic = _u16(hdr, opt + 0x00)
    if not (magic == 0x20B and mach == 0x8664):
        return (False, 0, 0, 0, 0, 0)
    exp_rva = _u32(hdr, opt + 0x70 + 0)  # export dir RVA
    exp_sz  = _u32(hdr, opt + 0x70 + 4)
    return (True, exp_rva, exp_sz, nsect, opt, optsz)

def _rva_to_off_mapped(rva, sections, data_len):
    random.shuffle(sections)
    for va, vsz, ptr, rsz in sections:
        end = va + max(vsz, rsz)
        if va <= rva < end and 0 <= ptr < data_len:
            off = ptr + (rva - va)
            if 0 <= off < data_len:
                return off
    return None

def parse_exports_x64_fast(path, max_names=MAX_EXPORTS_PER_DLL):
    """
    mmap the file; grab at most max_names exported function names
    (skip forwarded exports). Returns (True, names) for x64 DLLs,
    or (False, []) otherwise.
    """
    try:
        with open(path, "rb") as f:
            ok, exp_rva, exp_sz, nsects, opt, optsz = _quick_is_x64_and_has_exports(f)
            if not ok or exp_rva == 0:
                return (False, [])
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    except Exception:
        return (False, [])
    data = mm

    # section headers
    shoff = opt + optsz
    sections = []
    for i in range(nsects):
        so = shoff + i*40
        if so + 40 > len(data): break
        vsz  = _u32(data, so + 0x08)
        va   = _u32(data, so + 0x0C)
        rsz  = _u32(data, so + 0x10)
        ptr  = _u32(data, so + 0x14)
        sections.append((va, vsz, ptr, rsz))

    exp_off = _rva_to_off_mapped(exp_rva, sections, len(data))
    if exp_off is None or exp_off + 40 > len(data):
        mm.close(); return (True, [])

    num_funcs = _u32(data, exp_off + 0x14)
    num_names = _u32(data, exp_off + 0x18)
    aof_rva   = _u32(data, exp_off + 0x1C)
    aon_rva   = _u32(data, exp_off + 0x20)
    aoo_rva   = _u32(data, exp_off + 0x24)
    if num_names == 0 or not (aof_rva and aon_rva and aoo_rva):
        mm.close(); return (True, [])

    aof = _rva_to_off_mapped(aof_rva, sections, len(data))
    aon = _rva_to_off_mapped(aon_rva, sections, len(data))
    aoo = _rva_to_off_mapped(aoo_rva, sections, len(data))
    if None in (aof, aon, aoo):
        mm.close(); return (True, [])

    names = []
    exp_end = exp_rva + max(1, exp_sz)
    limit = min(num_names, max_names)
    indices = range(num_names)
    if num_names > limit:
        try:
            indices = random.sample(range(num_names), limit)
        except ValueError:
            indices = range(limit)
    for i in indices:

        name_rva = _u32(data, aon + 4*i)
        name_off = _rva_to_off_mapped(name_rva, sections, len(data))
        if name_off is None: continue
        j = name_off
        try:
            while j < len(data) and data[j] != 0: j += 1
            nm = bytes(data[name_off:j]).decode("ascii", errors="strict")
        except Exception:
            continue
        if not nm: continue
        ord_ = _u16(data, aoo + 2*i)
        if ord_ >= num_funcs: continue
        fn_rva = _u32(data, aof + 4*ord_)
        if exp_rva <= fn_rva < exp_end:  # forwarder
            continue
        names.append(nm)

    mm.close()
    names = list(dict.fromkeys(names))
    return (True, names)

def scan_x64_dlls_fast(root):
    """
    Stream the tree, prune dirs, stop early by TARGET_DLLS or SCAN_TIME_BUDGET_SEC.
    Returns list[(path, [names])].
    """
    t0 = time.time()
    picked = []

    def should_skip_dir(dname):
        return dname.lower() in {n.lower() for n in EXCLUDE_DIR_NAMES}

    if not RECURSIVE:
        try:
            with os.scandir(root) as it:
                random.shuffle(it)
                for e in it:
                    if len(picked) >= TARGET_DLLS or (time.time() - t0) > SCAN_TIME_BUDGET_SEC:
                        break
                    if not e.is_file() or not (e.name.lower().endswith(".dll")  or e.name.lower().endswith(".exe")):
                        continue
                    ok, names = parse_exports_x64_fast(e.path)
                    if ok and names:
                        picked.append((e.path, names))
        except:
            pass
        return picked

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]
        random.shuffle(filenames)
        for fn in filenames:
            if len(picked) >= TARGET_DLLS or (time.time() - t0) > SCAN_TIME_BUDGET_SEC:
                return picked
            if not (fn.lower().endswith(".dll") or fn.lower().endswith(".exe")): continue
            p = os.path.join(dirpath, fn)
            ok, names = parse_exports_x64_fast(p)
            if ok and names:
                picked.append((p, names))
    return picked

# --- child worker: load DLL & call random export a few times ---
def child_worker(path_str, func_name, iterations, max_args, max_buf, seed):
    random.seed(seed)
    path = Path(path_str)
    if PREPEND_DLL_DIR_TO_PATH:
        os.environ["PATH"] = str(path.parent) + os.pathsep + os.environ.get("PATH", "")
    try:
        lib = ctypes.WinDLL(str(path))  # simple load; PATH already primed
    except Exception:
        return
    try:
        fn = getattr(lib, func_name)
    except Exception:
        return
    fn.restype = ctypes.c_uint64  # generic 64-bit return

    bufs = []
    for _ in range(8):
        sz = random.randint(0, max(1, max_buf))
        buf = ctypes.create_string_buffer(os.urandom(sz) if sz > 0 else b"")
        bufs.append(buf)

    for _ in range(iterations):
        nargs = random.randint(0, max_args)
        args = []
        for __ in range(nargs):
            kind = random.randint(0, 4)
            if kind == 0:
                args.append(ctypes.c_uint64(random.getrandbits(64)))
            elif kind == 1:
                args.append(ctypes.c_uint64(random.randrange(0, 0x10000)))
            elif kind == 2:
                args.append(ctypes.c_void_p(0))  # NULL
            elif kind == 3:
                b = random.choice(bufs)
                args.append(ctypes.cast(b, ctypes.c_void_p))
            else:
                b = random.choice(bufs)
                pptr = ctypes.pointer(ctypes.c_void_p(ctypes.addressof(b)))
                args.append(ctypes.cast(pptr, ctypes.c_void_p))
        try:
            _ = fn(*args)
        except Exception:
            pass  # child can crash/hang; orchestrator will replace it

# --- orchestration ---
def spawn_one(dlls, calls_per_child, max_args, max_buf):
    path, names = random.choice(dlls)
    func = random.choice(names)
    seed = random.getrandbits(64)
    proc = mp.Process(
        target=child_worker,
        args=(path, func, calls_per_child, max_args, max_buf, seed),
        daemon=True
    )
    proc.start()
    return proc, path, func, time.time()

def orchestrate():
    if os.name != "nt":
        print("[-] Windows-only.", file=sys.stderr); sys.exit(2)
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print("[-] Use 64-bit Python to call x64 DLLs.", file=sys.stderr); sys.exit(2)
    if RNG_SEED is not None:
        random.seed(RNG_SEED)

    dlls = scan_x64_dlls_fast(ROOT_DIR)
    if not dlls:
        print("[-] No suitable DLLs found."); sys.exit(1)

    procs = []
    t0 = time.time()
    # prefill
    for _ in range(WORKERS):
        try:
            p, path, fn, started = spawn_one(dlls, CALLS_PER_CHILD, MAX_ARGS_PER_CALL, MAX_RANDOM_BUF_BYTES)
            procs.append((p, path, fn, started))
        except Exception:
            pass

    while time.time() - t0 < TOTAL_DURATION_SEC:
        time.sleep(0.05)
        new = []
        now = time.time()
        for (p, path, fn, started) in procs:
            alive = p.is_alive()
            timed_out = (now - started) > CHILD_TIMEOUT_SEC
            if not alive or timed_out:
                if alive and timed_out:
                    try: p.terminate()
                    except Exception: pass
                try:
                    np, npath, nfn, nstart = spawn_one(dlls, CALLS_PER_CHILD, MAX_ARGS_PER_CALL, MAX_RANDOM_BUF_BYTES)
                    new.append((np, npath, nfn, nstart))
                except Exception:
                    pass
            else:
                new.append((p, path, fn, started))
        procs = new

    # cleanup
    for (p, _, _, _) in procs:
        if p.is_alive():
            try: p.terminate()
            except Exception: pass

def main():
    mp.freeze_support()
    mp.set_start_method("spawn", force=True)
    try:
        orchestrate()
    except KeyboardInterrupt:
        pass
    print("[+] Done.")

if __name__ == "__main__":
    main()
