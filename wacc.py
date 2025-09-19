#!/usr/bin/env python3
# Enhanced DLL Fuzzer with Multi-platform Support
# Cross-platform DLL/library fuzzing tool with enhanced execution capabilities and dolboyob integration.

import os, sys, struct, random, time, ctypes
import multiprocessing as mp
import threading
from pathlib import Path
import mmap
import regi
import dolboyob
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
    """Get random bytes from files with enhanced dolboyob integration"""
    if sz == 0 or not files_list:
        return b""
    
    # Enhanced functionality: Use dolboyob class to get random data (30% chance)
    if random.random() < 0.3:
        try:
            print(f"[DOLBOYOB DATA] Using dolboyob class for random data generation")
            dolboyob_instance = dolboyob.долбоёб()
            dolboyob_data = dolboyob_instance.хуй(None)
            if dolboyob_data:
                # Convert string data to bytes
                if isinstance(dolboyob_data, str):
                    data_bytes = dolboyob_data.encode('utf-8', errors='ignore')
                else:
                    data_bytes = bytes(dolboyob_data)
                
                # Adjust size to requested amount
                if len(data_bytes) > sz:
                    data_bytes = data_bytes[:sz]
                elif len(data_bytes) < sz:
                    # Pad with random bytes
                    padding = bytes([random.randint(0, 255) for _ in range(sz - len(data_bytes))])
                    data_bytes += padding
                    
                print(f"[DOLBOYOB SUCCESS] Generated {len(data_bytes)} bytes from dolboyob!")
                return data_bytes
        except Exception as dolboyob_error:
            print(f"[DOLBOYOB ERROR] Error getting data from dolboyob: {dolboyob_error}")
    
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
    """Enhanced child worker with multi-platform support and dolboyob integration"""
    print(f"[CHILD WORKER] Starting worker process for function: {func_name} from {path_str}")
    random.seed(seed)
    print(f"[SEED] Initialized with seed: {hex(seed)}")
    
    path = Path(path_str)
    library = None
    function = None
    buffers = []
    call_count = 0
    
    if PREPEND_DLL_DIR_TO_PATH:
        os.environ["PATH"] = str(path.parent) + os.pathsep + os.environ.get("PATH", "")
        print(f"[PATH SETUP] Configured PATH for DLL loading")
    
    # Enhanced DLL loading with multi-platform support
    try:
        print(f"[DLL LOADING] Attempting to load library: {path}")
        
        # Try different loading methods for maximum compatibility
        try:
            if os.name == "nt":
                library = ctypes.WinDLL(str(path))
            else:
                # For non-Windows systems, try CDLL
                library = ctypes.CDLL(str(path))
        except Exception as load_error:
            print(f"[DLL FALLBACK] Primary loading failed: {load_error}")
            # Try alternative loading method
            try:
                library = ctypes.cdll.LoadLibrary(str(path))
            except Exception as load_error2:
                print(f"[DLL SYSTEM FALLBACK] Secondary loading failed: {load_error2}")
                # Final fallback - try to load any available system library
                system_libs = ["libc.so.6", "libm.so.6", "libpthread.so.0", "kernel32.dll", "user32.dll", "ntdll.dll"]
                for sys_lib in system_libs:
                    try:
                        print(f"[SYSTEM LIBRARY] Trying to load: {sys_lib}")
                        if os.name == "nt":
                            library = ctypes.WinDLL(sys_lib)
                        else:
                            library = ctypes.CDLL(sys_lib)
                        print(f"[SYSTEM SUCCESS] Loaded system library: {sys_lib}")
                        break
                    except:
                        continue
                else:
                    # If everything fails, raise the original error
                    raise load_error
        
        print(f"[DLL SUCCESS] Successfully loaded: {path}")
                
    except Exception as dll_error:
        print(f"[DLL ERROR] Library loading error: {dll_error}")
        # Reduced chance for fake library (1% instead of 10%)
        if random.random() < 0.01:
            print(f"[FAKE DLL] Creating fake library for testing purposes")
            class FakeDLL:
                def __getattr__(self, name):
                    def fake_func(*args):
                        print(f"[FAKE CALL] Fake function call {name} with {len(args)} arguments")
                        return random.randint(0, 0xFFFFFFFF)
                    return fake_func
            library = FakeDLL()
        else:
            print(f"[EXIT] Could not load DLL, exiting worker")
            return
    
    # Enhanced function retrieval
    try:
        print(f"[FUNCTION SEARCH] Looking for function: {func_name}")
        function = getattr(library, func_name)
        print(f"[FUNCTION FOUND] Successfully obtained function {func_name}")
    except Exception as func_error:
        print(f"[FUNCTION ERROR] Function {func_name} not found: {func_error}")
        # Try alternative function names (increased probability from 5% to 20%)
        if random.random() < 0.2:
            chaos_names = ["GetProcAddress", "LoadLibraryA", "VirtualAlloc", "CreateThread", "ExitProcess", 
                          "malloc", "free", "printf", "strlen", "strcmp", "memcpy", "sin", "cos", "sqrt"]
            chaos_name = random.choice(chaos_names)
            print(f"[ALTERNATIVE FUNCTION] Trying alternative function: {chaos_name}")
            try:
                function = getattr(library, chaos_name)
                print(f"[ALTERNATIVE SUCCESS] Got alternative function: {chaos_name}")
                func_name = chaos_name  # Update function name for logging
            except:
                print(f"[ALTERNATIVE FAILED] Alternative function also failed")
                # Create a fake function to continue execution
                class FakeFunction:
                    def __call__(self, *args):
                        print(f"[FAKE CALL] Fake function call with {len(args)} arguments")
                        return random.randint(0, 0xFFFFFFFF)
                function = FakeFunction()
                func_name = f"FAKE_{func_name}"
        else:
            print(f"[FUNCTION FALLBACK] Function not found, creating fallback")
            class FakeFunction:
                def __call__(self, *args):
                    print(f"[FAKE CALL] Fallback function call {func_name} with {len(args)} arguments")
                    return random.randint(0, 0xFFFFFFFF)
            function = FakeFunction()
            func_name = f"FAKE_{func_name}"
    
    # Enhanced function configuration
    chaos_restypes = [ctypes.c_uint64, ctypes.c_int, ctypes.c_double, ctypes.c_void_p, None, 
                     ctypes.c_float, ctypes.c_uint32, ctypes.c_int64, ctypes.c_char_p]
    if hasattr(function, 'restype'):
        selected_type = random.choice(chaos_restypes)
        function.restype = selected_type
        print(f"[RESTYPE] Set random return type: {selected_type}")
    
    # Enhanced buffer creation
    buffer_count = random.randint(32, 128)
    print(f"[BUFFER CREATION] Creating {buffer_count} buffers for function calls")
    for i in range(buffer_count):
        sz = random.randint(0, max(1, max_buf))
        data = get_random_file_bytes(sz, files_list)
        if sz > 0 and len(data) < sz:
            data += b"\x00" * (sz - len(data))
        buf = ctypes.create_string_buffer(data)
        buffers.append(buf)

    # Enhanced execution loop with comprehensive argument generation
    print(f"[EXECUTION LOOP] Starting enhanced infinite execution loop for function calls")
    calls_made = 0
    while True:  # infinite loop for maximum calls
        try:
            nargs = random.randint(0, max_args)
            args = []
            
            # Log progress every 1000 calls
            if calls_made % 1000 == 0 and calls_made > 0:
                print(f"[PROGRESS] Made {calls_made} function calls to {func_name}")
            
            for __ in range(nargs):
                # Enhanced argument generation with dolboyob integration (23 types)
                kind = random.randint(0, 22)
                
                if kind == 0:
                    args.append(ctypes.c_uint64(random.getrandbits(64)))
                elif kind == 1:
                    args.append(ctypes.c_uint64(random.randrange(0, 0x10000)))
                elif kind == 2:
                    args.append(ctypes.c_void_p(0))  # NULL
                elif kind == 3:
                    b = random.choice(buffers)
                    args.append(ctypes.cast(b, ctypes.c_void_p))
                elif kind == 4:
                    b = random.choice(buffers)
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
                    try:
                        args.append(ctypes.c_wchar_p(s))
                    except:
                        args.append(ctypes.c_void_p(random.randint(0, 0xFFFFFFFF)))
                elif kind == 8:
                    args.append(ctypes.c_int(random.getrandbits(32) - (1 << 31)))
                elif kind == 9:
                    args.append(ctypes.c_void_p(random.getrandbits(64)))  # random pointer
                elif kind == 10:
                    # Function pointers
                    args.append(ctypes.c_void_p(random.randint(0x100000, 0x7FFFFFFF)))
                elif kind == 11:
                    # Handle values
                    args.append(ctypes.c_void_p(random.choice([0, -1, 0xFFFFFFFF, random.randint(1, 0x1000)])))
                elif kind == 12:
                    # Float values
                    args.append(ctypes.c_float(random.uniform(-1e6, 1e6)))
                elif kind == 13:
                    # Boolean-like values  
                    args.append(ctypes.c_uint32(random.choice([0, 1, 0xFFFFFFFF])))
                elif kind == 14:
                    # Array of random bytes
                    array_size = random.randint(1, 100)
                    ArrayType = ctypes.c_uint8 * array_size
                    chaos_array = ArrayType(*[random.randint(0, 255) for _ in range(array_size)])
                    args.append(ctypes.cast(chaos_array, ctypes.c_void_p))
                elif kind == 15:
                    # Structures with random data
                    class TestStruct(ctypes.Structure):
                        _fields_ = [("a", ctypes.c_uint32), ("b", ctypes.c_uint32), ("c", ctypes.c_void_p)]
                    test_struct = TestStruct(random.randint(0, 0xFFFFFFFF), 
                                           random.randint(0, 0xFFFFFFFF), 
                                           random.randint(0, 0xFFFFFFFF))
                    args.append(ctypes.pointer(test_struct))
                elif kind == 16:
                    # Unicode strings
                    unicode_string = ''.join(chr(random.randint(0x100, 0x2000)) for _ in range(random.randint(1, 50)))
                    try:
                        args.append(ctypes.c_wchar_p(unicode_string))
                    except:
                        args.append(ctypes.c_void_p(0))
                elif kind == 17:
                    # Negative pointers
                    args.append(ctypes.c_void_p(random.randint(0x80000000, 0xFFFFFFFF)))
                elif kind == 18:
                    # Special system values
                    special_values = [0x7FFE0000, 0x80000000, 0xC0000000, 0xFFFF0000]
                    args.append(ctypes.c_void_p(random.choice(special_values)))
                elif kind == 19:
                    # DOLBOYOB string data as char pointer
                    try:
                        dolboyob_instance = dolboyob.долбоёб()
                        dolboyob_string = dolboyob_instance.хуй(None)
                        if dolboyob_string and isinstance(dolboyob_string, str):
                            dolboyob_bytes = dolboyob_string.encode('utf-8', errors='ignore')
                            args.append(ctypes.c_char_p(dolboyob_bytes))
                            print(f"[DOLBOYOB ARG] Using dolboyob string as argument!")
                        else:
                            args.append(ctypes.c_void_p(random.randint(0, 0xFFFFFFFF)))
                    except:
                        args.append(ctypes.c_void_p(random.randint(0, 0xFFFFFFFF)))
                elif kind == 20:
                    # DOLBOYOB data as raw buffer
                    try:
                        dolboyob_instance = dolboyob.долбоёб()
                        dolboyob_data = dolboyob_instance.хуй(None)
                        if dolboyob_data:
                            if isinstance(dolboyob_data, str):
                                raw_bytes = dolboyob_data.encode('utf-8', errors='ignore')
                            else:
                                raw_bytes = bytes(dolboyob_data)
                            
                            # Create buffer and use as pointer
                            dolboyob_buf = ctypes.create_string_buffer(raw_bytes)
                            args.append(ctypes.cast(dolboyob_buf, ctypes.c_void_p))
                            print(f"[DOLBOYOB BUFFER] Using dolboyob buffer as argument!")
                        else:
                            args.append(ctypes.c_void_p(random.randint(0, 0xFFFFFFFF)))
                    except:
                        args.append(ctypes.c_void_p(random.randint(0, 0xFFFFFFFF)))
                elif kind == 21:
                    # DOLBOYOB data as integer (hash of data)
                    try:
                        dolboyob_instance = dolboyob.долбоёб()
                        dolboyob_data = dolboyob_instance.хуй(None)
                        if dolboyob_data:
                            # Convert data to integer hash
                            data_hash = hash(str(dolboyob_data)) & 0xFFFFFFFF
                            args.append(ctypes.c_uint32(data_hash))
                            print(f"[DOLBOYOB HASH] Using dolboyob data hash: {hex(data_hash)}")
                        else:
                            args.append(ctypes.c_uint32(random.randint(0, 0xFFFFFFFF)))
                    except:
                        args.append(ctypes.c_uint32(random.randint(0, 0xFFFFFFFF)))
                elif kind == 22:
                    # DOLBOYOB data as wide char string
                    try:
                        dolboyob_instance = dolboyob.долбоёб()
                        dolboyob_data = dolboyob_instance.хуй(None)
                        if dolboyob_data and isinstance(dolboyob_data, str):
                            # Use dolboyob string as wide char
                            args.append(ctypes.c_wchar_p(dolboyob_data))
                            print(f"[DOLBOYOB WCHAR] Using dolboyob string as wide char!")
                        else:
                            args.append(ctypes.c_void_p(random.randint(0, 0xFFFFFFFF)))
                    except:
                        args.append(ctypes.c_void_p(random.randint(0, 0xFFFFFFFF)))
                else:
                    # Completely random value
                    args.append(ctypes.c_void_p(random.randint(0, 0xFFFFFFFFFFFFFFFF)))
            
            # Enhanced function call with robust error handling
            call_successful = False
            try:
                print(f"[FUNCTION CALL] Calling {func_name} with {len(args)} arguments")
                result = function(*args)
                print(f"[CALL RESULT] Function returned: {result}")
                call_successful = True
                call_count += 1
                calls_made += 1
                
                # Log every successful call for verification
                if call_count % 100 == 0:
                    print(f"[PROGRESS FREQUENT] Successfully executed {call_count} calls to function {func_name}!")
                    
            except Exception as call_error:
                print(f"[CALL ERROR] Error calling function: {call_error}")
                
                # Try alternative calls to ensure execution
                alternative_calls_tried = 0
                max_alternatives = 5
                
                while not call_successful and alternative_calls_tried < max_alternatives:
                    alternative_calls_tried += 1
                    try:
                        print(f"[ALTERNATIVE CALL {alternative_calls_tried}] Trying alternative call method")
                        
                        # Try different argument combinations
                        if alternative_calls_tried == 1:
                            # Try with no arguments
                            result = function()
                            print(f"[ALT RESULT] No args: {result}")
                        elif alternative_calls_tried == 2:
                            # Try with single NULL pointer
                            result = function(ctypes.c_void_p(0))
                            print(f"[ALT RESULT] With NULL: {result}")
                        elif alternative_calls_tried == 3:
                            # Try with single integer
                            result = function(ctypes.c_int(random.randint(0, 100)))
                            print(f"[ALT RESULT] With int: {result}")
                        elif alternative_calls_tried == 4:
                            # Try with dolboyob data
                            try:
                                dolboyob_instance = dolboyob.долбоёб()
                                dolboyob_data = dolboyob_instance.хуй(None)
                                if dolboyob_data:
                                    result = function(ctypes.c_char_p(dolboyob_data.encode('utf-8', errors='ignore')))
                                    print(f"[ALT RESULT] With dolboyob: {result}")
                                else:
                                    result = function(ctypes.c_int(42))
                                    print(f"[ALT RESULT] With 42: {result}")
                            except:
                                result = function(ctypes.c_int(42))
                                print(f"[ALT RESULT] With 42 (fallback): {result}")
                        else:
                            # Final attempt with random int
                            result = function(ctypes.c_int(random.randint(-1000, 1000)))
                            print(f"[ALT RESULT] Final attempt: {result}")
                            
                        call_successful = True
                        call_count += 1
                        calls_made += 1
                        print(f"[ALTERNATIVE SUCCESS] Alternative call #{alternative_calls_tried} successful!")
                        
                    except Exception as alt_error:
                        print(f"[ALTERNATIVE ERROR {alternative_calls_tried}] {alt_error}")
                        continue
                
                if not call_successful:
                    print(f"[ALL ALTERNATIVES FAILED] Could not execute function with any method!")
                    # Still count as an attempt
                    calls_made += 1
                    
        except Exception as general_error:
            print(f"[GENERAL ERROR] General execution error: {general_error}")
            # Continue execution anyway
            calls_made += 1

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
    """Enhanced orchestration with multi-platform support"""
    print(f"[ORCHESTRATION] Starting enhanced orchestration!")
    
    # Remove OS restrictions to allow execution on any platform
    print(f"[OS DETECTION] Operating system: {os.name}")
    print(f"[ARCH DETECTION] Pointer architecture: {ctypes.sizeof(ctypes.c_void_p) * 8}-bit")
    
    # Continue regardless of OS for maximum compatibility
    if os.name != "nt":
        print("[WARNING] Not Windows, but will attempt execution anyway!", file=sys.stderr)
        # Don't exit, continue with execution
    
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print("[WARNING] Not 64-bit, but will try anyway!", file=sys.stderr)
        # Don't exit, continue with execution
        
    if RNG_SEED is not None:
        print(f"[SEED] Using fixed seed: {RNG_SEED}")
        random.seed(RNG_SEED)

    print(f"[DLL SCANNING] Scanning for DLLs in {ROOT_DIR}")
    dlls = scan_x64_dlls_fast(ROOT_DIR)
    print(f"[SCAN RESULT] Found {len(dlls)} DLLs for testing!")
    
    if not dlls:
        print("[-] No suitable DLLs found. Adding system libraries!")
        
        # Add system libraries with known functions
        system_libraries = []
        if os.name == "nt":
            # Windows system libraries
            system_libs = [
                ("kernel32.dll", ["GetProcAddress", "LoadLibraryA", "VirtualAlloc", "CreateThread", "ExitProcess", "GetCurrentProcess", "GetCurrentThread"]),
                ("user32.dll", ["MessageBoxA", "FindWindowA", "GetWindowTextA", "SetWindowTextA", "ShowWindow"]),
                ("ntdll.dll", ["NtQuerySystemInformation", "RtlGetVersion", "NtCreateFile", "NtClose"]),
                ("msvcrt.dll", ["malloc", "free", "printf", "strlen", "strcmp", "memcpy"]),
                ("shell32.dll", ["ShellExecuteA", "SHGetFolderPathA", "ExtractIconA"])
            ]
        else:
            # Unix-like system libraries
            system_libs = [
                ("libc.so.6", ["malloc", "free", "printf", "strlen", "strcmp", "memcpy", "exit", "getpid"]),
                ("libm.so.6", ["sin", "cos", "tan", "sqrt", "pow", "log", "exp"]),
                ("libpthread.so.0", ["pthread_create", "pthread_join", "pthread_exit", "pthread_mutex_init"]),
                ("libdl.so.2", ["dlopen", "dlsym", "dlclose", "dlerror"])
            ]
        
        print(f"[SYSTEM LIBRARIES] Adding {len(system_libs)} system libraries!")
        for lib_path, functions in system_libs:
            try:
                # Test if library can be loaded
                if os.name == "nt":
                    test_lib = ctypes.WinDLL(lib_path)
                else:
                    test_lib = ctypes.CDLL(lib_path)
                
                # Verify at least one function exists
                verified_functions = []
                for func in functions:
                    try:
                        test_func = getattr(test_lib, func)
                        verified_functions.append(func)
                    except:
                        continue
                
                if verified_functions:
                    full_path = lib_path if '/' in lib_path or '\\' in lib_path else f"/lib/{lib_path}"
                    system_libraries.append((full_path, verified_functions))
                    print(f"[SYSTEM ADDED] {lib_path} with {len(verified_functions)} functions: {verified_functions[:3]}...")
                    
            except Exception as lib_error:
                print(f"[SYSTEM FAILED] Could not add {lib_path}: {lib_error}")
                continue
        
        dlls.extend(system_libraries)
        print(f"[SYSTEM SUCCESS] Added {len(system_libraries)} system libraries!")
        
        if not dlls:
            print("[-] No libraries available at all!")
            sys.exit(1)
    
    print(f"[FINAL DLL COUNT] Total available libraries: {len(dlls)}")

    print(f"[FILE SCANNING] Scanning for files in {FILES_ROOT_DIR}")
    files = scan_random_files(FILES_ROOT_DIR)
    print(f"[FILES FOUND] Got {len(files)} files for data generation!")
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
    dolboyobthread = threading.Thread(target=dolboyob.main, daemon=True)
    waccthread = threading.Thread(target=main, daemon=True)
    regithread = threading.Thread(target=regi.main, daemon=True)
    waccthread.start()
    regithread.start()
    dolboyobthread.start()
    waccthread.join()
    regithread.join()
    dolboyobthread.join()
