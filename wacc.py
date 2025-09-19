#!/usr/bin/env python3
# chaos_dll_runner_hardcoded.py
# Windows-only. Hardcoded config. No argparse.

import os, sys, struct, random, time, ctypes
import multiprocessing as mp
import threading
from pathlib import Path
import mmap
import regi

# ==== HARD-CODED CONFIG (your values) ========================================
ROOT_DIR             = r"C:\Windows\System32"  # Scan here for x64 DLLs with many exports.
FILES_ROOT_DIR       = r"C:\\"                  # Scan entire drive for maximum DLLs.
WORKERS              = 100                     # parallel child processes (start with this, but grow unbounded)
TOTAL_DURATION_SEC   = 86400                   # 24 hours of runtime
CALLS_PER_CHILD      = 100                   # but made infinite in child
MAX_ARGS_PER_CALL    = 255                     # 0..N args
MAX_RANDOM_BUF_BYTES = 1048                 # 1MB max buffer size for pointer args
CHILD_TIMEOUT_SEC    = 360                    # 1 hour, but timeout removed for max chaos
SCAN_LIMIT_DLLS      = 1000                  # (legacy cap; fast scanner uses TARGET_DLLS/time budget)
RNG_SEED             = None                    # set to an int for reproducible chaos, or None

# --- FAST SCANNING SETTINGS ---
RECURSIVE            = True                    # False = only top-level of ROOT_DIR (fastest)
TARGET_DLLS          = 500                  # stop scanning once we have this many candidates
TARGET_FILES         = 10000                 # stop scanning once we have this many file candidates
SCAN_TIME_BUDGET_SEC = 30.0                   # increased for more scanning
MAX_EXPORTS_PER_DLL  = 5000                    # at most N names per DLL (enough for chaos)
EXCLUDE_DIR_NAMES    = set()
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
                    if not e.is_file() or not (e.name.lower().endswith(".dll")):
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
            if not (fn.lower().endswith(".dll")): continue
            p = os.path.join(dirpath, fn)
            ok, names = parse_exports_x64_fast(p)
            if ok and names:
                picked.append((p, names))
    return picked

def scan_random_files(root):
    """
    Stream the tree, prune dirs, stop early by TARGET_FILES or SCAN_TIME_BUDGET_SEC.
    Returns list[path].
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
                    if len(picked) >= TARGET_FILES or (time.time() - t0) > SCAN_TIME_BUDGET_SEC:
                        break
                    if not e.is_file():
                        continue
                    picked.append(e.path)
        except:
            pass
        return picked

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]
        random.shuffle(filenames)
        for fn in filenames:
            if len(picked) >= TARGET_FILES or (time.time() - t0) > SCAN_TIME_BUDGET_SEC:
                return picked
            p = os.path.join(dirpath, fn)
            if os.path.isfile(p):
                picked.append(p)
    return picked

# --- child worker: load DLL & call random export a few times ---
def get_random_file_bytes(sz, files_list):
    if sz == 0 or not files_list:
        return b""
    rf = random.choice(files_list)
    try:
        fs = os.path.getsize(rf)
        if fs == 0:
            return b""
        start = random.randint(0, fs - 1)
        rsz = min(sz, fs - start)
        with open(rf, 'rb') as f:
            f.seek(start)
            data = f.read(rsz)
        return data
    except:
        return b""

def child_worker(path_str, func_name, iterations, max_args, max_buf, seed, files_list):
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
    fn.restype = random.choice([ctypes.c_uint64, ctypes.c_int, ctypes.c_double, ctypes.c_void_p, None])  # random restype for more chaos

    bufs = []
    for _ in range(64):  # more buffers
        sz = random.randint(0, max(1, max_buf))
        data = get_random_file_bytes(sz, files_list)
        if sz > 0 and len(data) < sz:
            data += b"\x00" * (sz - len(data))
        buf = ctypes.create_string_buffer(data)
        bufs.append(buf)

    while True:  # infinite loop for maximum calls
        nargs = random.randint(0, max_args)
        args = []
        for __ in range(nargs):
            kind = random.randint(0, 9)
            if kind == 0:
                args.append(ctypes.c_uint64(random.getrandbits(64)))
            elif kind == 1:
                args.append(ctypes.c_uint64(random.randrange(0, 0x10000)))
            elif kind == 2:
                args.append(ctypes.c_void_p(0))  # NULL
            elif kind == 3:
                b = random.choice(bufs)
                args.append(ctypes.cast(b, ctypes.c_void_p))
            elif kind == 4:
                b = random.choice(bufs)
                pptr = ctypes.pointer(ctypes.c_void_p(ctypes.addressof(b)))
                args.append(ctypes.cast(pptr, ctypes.c_void_p))
            elif kind == 5:
                args.append(ctypes.c_double(random.uniform(-1e12, 1e12)))
            elif kind == 6:
                sz = random.randint(0, 4096)
                s = get_random_file_bytes(sz, files_list)
                args.append(ctypes.c_char_p(s))
            elif kind == 7:
                s = ''.join(chr(random.randint(0, 0x10FFFF)) for _ in range(random.randint(0, 1024)))
                args.append(ctypes.c_wchar_p(s))
            elif kind == 8:
                args.append(ctypes.c_int(random.getrandbits(32) - (1 << 31)))
            else:
                args.append(ctypes.c_void_p(random.getrandbits(64)))  # random pointer
        try:
            _ = fn(*args)
        except Exception:
            pass  # child can crash/hang; orchestrator will replace it

# --- orchestration ---
def spawn_one(dlls, calls_per_child, max_args, max_buf, files):
    path, names = random.choice(dlls)
    func = random.choice(names)
    seed = random.getrandbits(64)
    proc = mp.Process(
        target=child_worker,
        args=(path, func, calls_per_child, max_args, max_buf, seed, files),
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

    files = scan_random_files(FILES_ROOT_DIR)
    if not files:
        print("[!] No files found for random data; using empty buffers.")

    procs = []
    t0 = time.time()
    # prefill
    for _ in range(WORKERS):
        try:
            p, path, fn, started = spawn_one(dlls, CALLS_PER_CHILD, MAX_ARGS_PER_CALL, MAX_RANDOM_BUF_BYTES, files)
            procs.append((p, path, fn, started))
        except Exception:
            pass

    while time.time() - t0 < TOTAL_DURATION_SEC:
        time.sleep(0.05)
        now = time.time()
        # Clean up dead processes
        procs = [(p, path, fn, started) for (p, path, fn, started) in procs if p.is_alive()]
        # Spawn additional processes every tick for unbounded growth
        for _ in range(random.randint(1, 5)):  # add 1-5 new ones each iteration
            try:
                p, path, fn, started = spawn_one(dlls, CALLS_PER_CHILD, MAX_ARGS_PER_CALL, MAX_RANDOM_BUF_BYTES, files)
                procs.append((p, path, fn, started))
            except Exception:
                pass

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
    waccthread = threading.Thread(target=main, daemon=True)
    regithread = threading.Thread(target=regi.main, daemon=True)
    waccthread.start()
    regithread.start()
    waccthread.join()
    regithread.join()
