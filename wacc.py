#!/usr/bin/env python3
# Enhanced DLL Fuzzer with Comprehensive Function Enumeration and Parallel Execution
# Windows DLL fuzzing tool with complete function enumeration, timed reshuffling, and parallel execution

import os, sys, struct, random, time, ctypes
import multiprocessing as mp
import threading
from pathlib import Path
import mmap
import dolboyob
# ==== HARD-CODED CONFIG ========================================
ROOT_DIR             = r"C:\Windows\System32"           # Scan Windows dir for DLLs.
WORKERS              = 10                      # parallel child processes for function execution
TOTAL_DURATION_SEC   = 86400                   # 24 hours of runtime
MAX_ARGS_PER_CALL    = 25                     # 0..N args
MAX_RANDOM_BUF_BYTES = 1048576                 # 1MB max buffer size for pointer args
CHILD_TIMEOUT_SEC    = 30                     # 30 second timeout per child process
RNG_SEED             = None                    # set to an int for reproducible chaos, or None

# --- FUNCTION ENUMERATION AND EXECUTION SETTINGS ---
RECURSIVE            = True                    # Scan recursively
TARGET_DLLS          = 500                     # stop scanning once we have this many candidates
SCAN_TIME_BUDGET_SEC = 5.0                    # time budget for DLL scanning
MAX_EXPORTS_PER_DLL  = 5000                   # at most N names per DLL
EXCLUDE_DIR_NAMES    = set()
MAX_SCAN_DEPTH       = 3                      # max subdirectory depth for DLL scanning
TARGET_FILES         = 1000                   # max files to scan for random data

# --- TIMING CONTROLS ---
SHUFFLE_INTERVAL_SEC = 12                     # shuffle DLL/function array every 12 seconds
RANDOMIZE_INTERVAL_SEC = 13                   # re-randomize parameter data every 13 seconds
EXECUTION_BATCH_SIZE = 10                     # execute 10 functions in parallel

# Optional, but helps DLL dependency resolution: prepend each target DLL's dir to PATH in the child
PREPEND_DLL_DIR_TO_PATH = True

# Global data structures for function enumeration and execution
dll_function_array = []                        # Array of (dll_path, function_name) tuples
current_parameter_sets = []                    # Pre-generated parameter sets
last_shuffle_time = 0                         # Last time we shuffled the function array
last_randomize_time = 0                       # Last time we randomized parameters
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
                    if not e.is_file() or not (e.name.lower().endswith(".dll") or e.name.lower().endswith(".ocx") or e.name.lower().endswith(".sys") or e.name.lower().endswith(".exe")):
                        continue
                    ok, names = parse_exports_x64_fast(e.path)
                    if ok and names:
                        picked.append((e.path, names))
        except:
            pass
        return picked

    for dirpath, dirnames, filenames in os.walk(root):
        # Check depth limit
        depth = dirpath[len(root):].count(os.sep)
        if depth >= MAX_SCAN_DEPTH:
            dirnames.clear()  # Don't go deeper
            continue
            
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]
        random.shuffle(filenames)
        for fn in filenames:
            if len(picked) >= TARGET_DLLS or (time.time() - t0) > SCAN_TIME_BUDGET_SEC:
                return picked
            if not (fn.lower().endswith(".dll")or e.name.lower().endswith(".ocx") or e.name.lower().endswith(".sys") or e.name.lower().endswith(".exe")): continue
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

def generate_randomized_input(files_list=None):
    """
    Generate comprehensive randomized inputs for DLL execution.
    Returns various types of data including binary blobs, strings, integers, and more.
    """
    input_type = random.randint(0, 25)  # 26 different input types
    
    if input_type == 0:
        # os.urandom() - cryptographically random bytes
        size = random.choice([4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096])
        data = os.urandom(size)
        print(f"[RANDOM INPUT] os.urandom({size}) -> {len(data)} bytes: {data[:20].hex()}...")
        return data
        
    elif input_type == 1:
        # Random ASCII string
        length = random.randint(5, 50)
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        string = ''.join(random.choice(chars) for _ in range(length))
        print(f"[RANDOM INPUT] ASCII string ({length} chars): '{string}'")
        return string
        
    elif input_type == 2:
        # Random blob from system file (including exact user examples)
        system_files = [
            r"C:\Windows\explorer.exe",
            r"C:\Windows\System32\kernel32.dll", 
            r"C:\Windows\System32\ntdll.dll",
            r"C:\Windows\System32\user32.dll",
            r"C:\Windows\System32\advapi32.dll",
            r"C:\Intel\Thunderbolt\setup.exe",
            r"C:\Windows\System32\shell32.dll",
            r"C:\Windows\System32\msvcrt.dll"
        ]
        
        # Add files from files_list if available
        if files_list:
            system_files.extend(files_list[:5])
        
        target_file = random.choice(system_files)
        try:
            if os.path.exists(target_file):
                file_size = os.path.getsize(target_file)
                if file_size > 1000:
                    # Include user's specific examples with higher probability
                    if "explorer.exe" in target_file.lower() and random.random() < 0.2:
                        chunk_size = 67 * 1024  # User's 67KB example
                        offset = random.randint(0, max(0, file_size - chunk_size))
                    elif "setup.exe" in target_file.lower() and random.random() < 0.2:
                        chunk_size = 42  # User's 42 bytes example
                        offset = 69 if file_size > 111 else random.randint(0, max(0, file_size - chunk_size))
                    else:
                        # Random size between 1KB and 100KB
                        chunk_size = random.randint(1024, min(100*1024, file_size))
                        offset = random.randint(0, max(0, file_size - chunk_size))
                    
                    with open(target_file, 'rb') as f:
                        f.seek(offset)
                        data = f.read(chunk_size)
                    
                    print(f"[RANDOM INPUT] {len(data)} bytes from {Path(target_file).name} at offset {offset}")
                    return data
        except:
            pass
        
        # Fallback to random bytes if file access fails
        size = random.randint(1024, 50*1024)
        data = os.urandom(size)
        print(f"[RANDOM INPUT] Fallback random bytes: {len(data)} bytes")
        return data
        
    elif input_type == 3:
        # Random integer (including special values like 69420)
        special_ints = [0, 1, -1, 69420, 42, 1337, 0xDEADBEEF, 0xCAFEBABE, 0x12345678, 
                       0xFFFFFFFF, 0x80000000, 2147483647, -2147483648]
        if random.random() < 0.3:
            value = random.choice(special_ints)
        else:
            value = random.randint(-2**31, 2**31-1)
        print(f"[RANDOM INPUT] Integer: {value} (0x{value & 0xFFFFFFFF:08X})")
        return value
        
    elif input_type == 4:
        # Random float
        special_floats = [0.0, 1.0, -1.0, 3.14159, 2.71828, float('inf'), float('-inf')]
        if random.random() < 0.2:
            value = random.choice(special_floats)
        else:
            value = random.uniform(-1e12, 1e12)
        print(f"[RANDOM INPUT] Float: {value}")
        return value
        
    elif input_type == 5:
        # Unicode string (various character sets)
        char_sets = [
            'абвгдеёжзийклмнопрстуфхцчшщъыьэюя',  # Cyrillic
            '你好世界中文测试',  # Chinese
            'αβγδεζηθικλμνξοπρστυφχψω',  # Greek
            '日本語テスト',  # Japanese
            'العربية',  # Arabic
        ]
        charset = random.choice(char_sets)
        length = random.randint(5, 30)
        string = ''.join(random.choice(charset) for _ in range(length))
        print(f"[RANDOM INPUT] Unicode string: '{string}'")
        return string
        
    elif input_type == 6:
        # NULL bytes
        size = random.choice([4, 8, 16, 32, 64, 128, 256])
        data = b'\x00' * size
        print(f"[RANDOM INPUT] NULL bytes: {size} bytes")
        return data
        
    elif input_type == 7:
        # 0xFF pattern
        size = random.choice([4, 8, 16, 32, 64, 128])
        data = b'\xFF' * size
        print(f"[RANDOM INPUT] 0xFF pattern: {size} bytes")
        return data
        
    elif input_type == 8:
        # DEADBEEF pattern
        pattern = b'\xDE\xAD\xBE\xEF'
        repeats = random.randint(1, 64)
        data = pattern * repeats
        print(f"[RANDOM INPUT] DEADBEEF pattern: {len(data)} bytes")
        return data
        
    elif input_type == 9:
        # Random memory address (user-mode range)
        addresses = [0x400000, 0x10000000, 0x7FFE0000, 0x77000000, 0x7C800000]
        base = random.choice(addresses)
        offset = random.randint(0, 0xFFFF)
        addr = base + offset
        print(f"[RANDOM INPUT] Memory address: 0x{addr:08X}")
        return addr
        
    elif input_type == 10:
        # Windows error codes
        error_codes = [0, 2, 5, 6, 87, 122, 123, 1, 3, 4, 32, 183, 267]
        code = random.choice(error_codes)
        print(f"[RANDOM INPUT] Windows error code: {code}")
        return code
        
    elif input_type == 11:
        # Random GUID-like structure
        guid_bytes = os.urandom(16)
        print(f"[RANDOM INPUT] GUID-like: {guid_bytes.hex()}")
        return guid_bytes
        
    elif input_type == 12:
        # Registry path strings
        paths = [
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows",
            "HKEY_CURRENT_USER\\Software\\Microsoft",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services",
            "HKCU\\Control Panel\\Desktop"
        ]
        path = random.choice(paths)
        print(f"[RANDOM INPUT] Registry path: '{path}'")
        return path
        
    elif input_type == 13:
        # Network-like data (IP addresses, ports)
        if random.random() < 0.5:
            ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
            print(f"[RANDOM INPUT] IP address: '{ip}'")
            return ip
        else:
            port = random.randint(1, 65535)
            print(f"[RANDOM INPUT] Port number: {port}")
            return port
            
    elif input_type == 14:
        # Timestamp data
        timestamps = [
            int(time.time()),  # Current time
            0,  # Epoch
            random.randint(946684800, 2147483647),  # Random time between 2000-2038
            0x7FFFFFFF,  # Max 32-bit timestamp
        ]
        ts = random.choice(timestamps)
        print(f"[RANDOM INPUT] Timestamp: {ts}")
        return ts
        
    elif input_type == 15:
        # Windows handle values
        handles = [0, 0xFFFFFFFF, 0x80000000, random.randint(1, 0xFFFF)]
        handle = random.choice(handles)
        print(f"[RANDOM INPUT] Handle value: 0x{handle:08X}")
        return handle
        
    elif input_type == 16:
        # File paths
        paths = [
            r"C:\Windows\System32",
            r"C:\Program Files",
            r"C:\Users\Public",
            r"\\.\pipe\mypipe",
            r"\\?\C:\test",
            r"C:\$Recycle.Bin"
        ]
        path = random.choice(paths)
        print(f"[RANDOM INPUT] File path: '{path}'")
        return path
        
    elif input_type == 17:
        # Structured data (like Windows RECT, POINT, etc.)
        struct_data = struct.pack('<IIII', 
                                 random.randint(0, 1920),  # x
                                 random.randint(0, 1080),  # y  
                                 random.randint(0, 1920),  # width
                                 random.randint(0, 1080))  # height
        print(f"[RANDOM INPUT] Structured data (RECT-like): {len(struct_data)} bytes")
        return struct_data
        
    elif input_type == 18:
        # Dolboyob integration
        try:
            dolboyob_instance = dolboyob.долбоёб()
            dolboyob_data = dolboyob_instance.хуй(None)
            if dolboyob_data:
                if isinstance(dolboyob_data, str):
                    data = dolboyob_data.encode('utf-8', errors='ignore')
                else:
                    data = bytes(dolboyob_data)
                print(f"[RANDOM INPUT] Dolboyob data: {len(data)} bytes")
                return data
        except:
            pass
        # Fallback
        data = os.urandom(random.randint(16, 256))
        print(f"[RANDOM INPUT] Dolboyob fallback: {len(data)} bytes")
        return data
        
    elif input_type == 19:
        # Large integer (64-bit)
        value = random.getrandbits(64)
        print(f"[RANDOM INPUT] Large integer: {value} (0x{value:016X})")
        return value
        
    elif input_type == 20:
        # Specific file chunk with exact offset (like user's example)
        target_files = [
            (r"C:\Windows\explorer.exe", "explorer.exe"),
            (r"C:\Intel\Thunderbolt\setup.exe", "setup.exe"),
            (r"C:\Windows\System32\kernel32.dll", "kernel32.dll"),
        ]
        
        file_path, file_name = random.choice(target_files)
        try:
            if os.path.exists(file_path):
                # Use specific sizes like in user's examples
                sizes = [42, 67*1024, 128, 1024, 4096]  # Including 67KB and 42 bytes
                offsets = [69, 0, 100, 256, 512, 1024]  # Including offset 69
                
                chunk_size = random.choice(sizes)
                offset = random.choice(offsets)
                
                file_size = os.path.getsize(file_path)
                if offset < file_size:
                    actual_size = min(chunk_size, file_size - offset)
                    with open(file_path, 'rb') as f:
                        f.seek(offset)
                        data = f.read(actual_size)
                    print(f"[RANDOM INPUT] {len(data)} bytes from {file_name} at offset {offset}")
                    return data
        except:
            pass
            
        # Fallback
        data = os.urandom(random.randint(32, 1024))
        print(f"[RANDOM INPUT] File chunk fallback: {len(data)} bytes")
        return data
        
    elif input_type == 21:
        # Random boolean-like values
        values = [0, 1, True, False]
        value = random.choice(values)
        print(f"[RANDOM INPUT] Boolean-like: {value}")
        return value
        
    elif input_type == 22:
        # Array-like data
        element_count = random.randint(1, 16)
        elements = [random.randint(0, 0xFFFF) for _ in range(element_count)]
        array_data = struct.pack(f'<{element_count}H', *elements)
        print(f"[RANDOM INPUT] Array data: {element_count} elements, {len(array_data)} bytes")
        return array_data
        
    elif input_type == 23:
        # Random string from predefined pool (including user's exact example)
        strings = [
            "tlasjfdlksjfokjaswoefjslfjape4p",  # User's exact example - higher probability
            "tlasjfdlksjfokjaswoefjslfjape4p",  # Duplicate for higher chance
            "randomstringdata123456789",
            "abcdefghijklmnopqrstuvwxyz", 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "1234567890!@#$%^&*()",
            "testdataforDLLexecution",
            "chaos_dll_random_string",
            "WindowsAPITestString",
            "kernel32_function_call",
            "ntdll_random_parameter"
        ]
        string = random.choice(strings)
        print(f"[RANDOM INPUT] Predefined string: '{string}'")
        return string
        ]
        string = random.choice(strings)
        print(f"[RANDOM INPUT] Predefined string: '{string}'")
        return string
        
    elif input_type == 24:
        # Random small buffer (typical for many APIs)
        size = random.choice([1, 2, 4, 8, 16, 32])
        data = os.urandom(size)
        print(f"[RANDOM INPUT] Small buffer: {size} bytes: {data.hex()}")
        return data
        
    else:  # input_type == 25
        # Mixed/composite data
        parts = []
        for _ in range(random.randint(2, 5)):
            part_size = random.randint(4, 32)
            parts.append(os.urandom(part_size))
        data = b''.join(parts)
        print(f"[RANDOM INPUT] Composite data: {len(data)} bytes from {len(parts)} parts")
        return data

def convert_to_ctypes(input_data):
    """Convert randomized input data to appropriate ctypes argument"""
    if isinstance(input_data, bytes):
        # Convert bytes to string buffer
        if len(input_data) > 0:
            return ctypes.create_string_buffer(input_data)
        else:
            return ctypes.c_void_p(0)
    elif isinstance(input_data, str):
        # Convert string to char pointer
        try:
            return ctypes.c_char_p(input_data.encode('utf-8', errors='ignore'))
        except:
            return ctypes.c_void_p(0)
    elif isinstance(input_data, int):
        # Convert integer to appropriate size
        if -2**31 <= input_data <= 2**31-1:
            return ctypes.c_int(input_data)
        elif 0 <= input_data <= 2**32-1:
            return ctypes.c_uint32(input_data)
        elif 0 <= input_data <= 2**64-1:
            return ctypes.c_uint64(input_data)
        else:
            return ctypes.c_void_p(input_data & 0xFFFFFFFFFFFFFFFF)
    elif isinstance(input_data, float):
        return ctypes.c_double(input_data)
    elif isinstance(input_data, bool):
        return ctypes.c_bool(input_data)
    else:
        # Fallback for unknown types
        return ctypes.c_void_p(random.randint(0, 0xFFFFFFFF))

def enumerate_all_dll_functions():
    """Enumerate every DLL and every function, store in array"""
    global dll_function_array
    print("[ENUMERATION] Starting comprehensive DLL and function enumeration...")
    
    dll_function_array = []
    dlls = scan_x64_dlls_fast(ROOT_DIR)
    
    if not dlls:
        print("[-] No suitable DLLs found during enumeration.")
        return
    
    total_functions = 0
    for dll_path, function_names in dlls:
        for func_name in function_names:
            dll_function_array.append((dll_path, func_name))
            total_functions += 1
    
    print(f"[ENUMERATION] Complete! Found {total_functions} functions across {len(dlls)} DLLs")
    print(f"[ENUMERATION] Sample functions: {dll_function_array[:5]}")

def shuffle_dll_function_array():
    """Shuffle the DLL/function array every 12 seconds"""
    global dll_function_array, last_shuffle_time
    current_time = time.time()
    
    if current_time - last_shuffle_time >= SHUFFLE_INTERVAL_SEC:
        print(f"[SHUFFLE] Shuffling {len(dll_function_array)} DLL functions...")
        random.shuffle(dll_function_array)
        last_shuffle_time = current_time
        print(f"[SHUFFLE] Complete! Next shuffle in {SHUFFLE_INTERVAL_SEC} seconds")

def prepare_parameter_sets(files_list):
    """Prepare 10 sets of randomized parameter data, re-randomize every 13 seconds"""
    global current_parameter_sets, last_randomize_time
    current_time = time.time()
    
    if current_time - last_randomize_time >= RANDOMIZE_INTERVAL_SEC:
        print(f"[RANDOMIZE] Preparing {EXECUTION_BATCH_SIZE} sets of randomized parameters...")
        current_parameter_sets = []
        
        for i in range(EXECUTION_BATCH_SIZE):
            # Generate parameter set with random number of arguments
            num_args = random.randint(0, MAX_ARGS_PER_CALL)
            param_set = []
            
            for j in range(num_args):
                try:
                    param_data = generate_randomized_input(files_list)
                    param_set.append(param_data)
                except Exception:
                    # Fallback to simple data on error
                    param_set.append(random.randint(0, 0xFFFFFFFF))
            
            current_parameter_sets.append(param_set)
        
        last_randomize_time = current_time
        print(f"[RANDOMIZE] Complete! {len(current_parameter_sets)} parameter sets ready")
        print(f"[RANDOMIZE] Next randomization in {RANDOMIZE_INTERVAL_SEC} seconds")

def execute_single_function(dll_path, func_name, param_set, files_list):
    """Execute a single DLL function with prepared parameters"""
    try:
        # Set random seed for this execution
        random.seed(random.getrandbits(32))
        
        # Load DLL
        path = Path(dll_path)
        if PREPEND_DLL_DIR_TO_PATH:
            os.environ["PATH"] = str(path.parent) + os.pathsep + os.environ.get("PATH", "")
        
        lib = ctypes.WinDLL(str(dll_path))
        fn = getattr(lib, func_name)
        fn.restype = random.choice([ctypes.c_uint64, ctypes.c_int, ctypes.c_double, ctypes.c_void_p, None])
        
        # Convert parameters to ctypes
        args = []
        for i, param_data in enumerate(param_set):
            try:
                converted_arg = convert_to_ctypes(param_data)
                args.append(converted_arg)
            except Exception:
                # Fallback to NULL on conversion error
                args.append(ctypes.c_void_p(0))
        
        # Execute function
        print(f"[EXECUTE] {func_name} from {Path(dll_path).name} with {len(args)} args")
        result = fn(*args)
        print(f"[SUCCESS] {func_name} executed successfully")
        return True
        
    except Exception as e:
        # Ignore all exceptions as requested
        print(f"[IGNORED] {func_name} failed: {str(e)[:50]}...")
        return False

def parallel_function_executor(files_list):
    """Execute 10 DLL functions in parallel with 30-second timeout"""
    global dll_function_array, current_parameter_sets
    
    if len(dll_function_array) < EXECUTION_BATCH_SIZE:
        print("[ERROR] Not enough functions enumerated for batch execution")
        return
    
    if len(current_parameter_sets) < EXECUTION_BATCH_SIZE:
        print("[ERROR] Not enough parameter sets prepared")
        return
    
    # Select 10 functions from the array
    functions_to_execute = dll_function_array[:EXECUTION_BATCH_SIZE]
    
    print(f"[PARALLEL] Starting parallel execution of {EXECUTION_BATCH_SIZE} functions...")
    
    # Create processes for parallel execution
    processes = []
    for i, ((dll_path, func_name), param_set) in enumerate(zip(functions_to_execute, current_parameter_sets)):
        try:
            proc = mp.Process(
                target=execute_single_function,
                args=(dll_path, func_name, param_set, files_list),
                daemon=True
            )
            proc.start()
            processes.append((proc, func_name))
        except Exception as e:
            print(f"[ERROR] Failed to start process for {func_name}: {e}")
    
    # Wait for all processes with timeout
    start_time = time.time()
    completed = 0
    timeout_count = 0
    
    for proc, func_name in processes:
        remaining_time = CHILD_TIMEOUT_SEC - (time.time() - start_time)
        if remaining_time <= 0:
            remaining_time = 1
        
        proc.join(timeout=remaining_time)
        if proc.is_alive():
            print(f"[TIMEOUT] {func_name} timed out, terminating...")
            proc.terminate()
            proc.join(timeout=1)
            if proc.is_alive():
                proc.kill()
            timeout_count += 1
        else:
            completed += 1
    
    execution_time = time.time() - start_time
    print(f"[PARALLEL] Batch complete: {completed} succeeded, {timeout_count} timed out in {execution_time:.2f}s")

# --- orchestration ---

def orchestrate():
    """Main orchestration loop with timed function enumeration, shuffling, and parallel execution"""
    global dll_function_array, current_parameter_sets, last_shuffle_time, last_randomize_time
    
    if os.name != "nt":
        print("[-] Windows-only.", file=sys.stderr); sys.exit(2)
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print("[-] Use 64-bit Python to call x64 DLLs.", file=sys.stderr); sys.exit(2)
    if RNG_SEED is not None:
        random.seed(RNG_SEED)

    print("[STARTUP] Enhanced DLL Fuzzer with Comprehensive Function Enumeration")
    print(f"[CONFIG] Shuffle interval: {SHUFFLE_INTERVAL_SEC}s, Randomize interval: {RANDOMIZE_INTERVAL_SEC}s")
    print(f"[CONFIG] Batch size: {EXECUTION_BATCH_SIZE}, Child timeout: {CHILD_TIMEOUT_SEC}s")

    # Get files for random data
    files = []
    try:
        files = scan_random_files(ROOT_DIR)
    except:
        pass
    if not files:
        print("[!] No files found for random data; using fallback methods.")

    # Initial enumeration of all DLL functions
    enumerate_all_dll_functions()
    if not dll_function_array:
        print("[-] No DLL functions found. Exiting."); sys.exit(1)

    # Initialize timing
    last_shuffle_time = time.time()
    last_randomize_time = time.time()
    
    # Prepare initial parameter sets
    prepare_parameter_sets(files)
    
    print(f"[READY] Starting main execution loop for {TOTAL_DURATION_SEC} seconds...")
    
    start_time = time.time()
    execution_cycle = 0
    
    while time.time() - start_time < TOTAL_DURATION_SEC:
        execution_cycle += 1
        cycle_start = time.time()
        
        print(f"\n[CYCLE {execution_cycle}] ===== Starting execution cycle =====")
        
        # 1. Check and shuffle DLL function array if needed (every 12 seconds)
        shuffle_dll_function_array()
        
        # 2. Check and prepare new parameter sets if needed (every 13 seconds)
        prepare_parameter_sets(files)
        
        # 3. Execute 10 DLL functions in parallel with 30-second timeout
        parallel_function_executor(files)
        
        cycle_time = time.time() - cycle_start
        elapsed_total = time.time() - start_time
        
        print(f"[CYCLE {execution_cycle}] Completed in {cycle_time:.2f}s. Total elapsed: {elapsed_total:.2f}s")
        
        # Brief pause before next cycle to prevent excessive CPU usage
        time.sleep(0.1)
    
    print(f"[COMPLETE] Fuzzing completed after {execution_cycle} cycles")

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
