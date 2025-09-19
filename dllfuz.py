#!/usr/bin/env python3
# Single DLL Fuzzer - focused fuzzing of a specific DLL file
# Based on wacc.py but modified to fuzz only one hardcoded DLL

import os
import sys
import struct
import random
import time
import ctypes
import multiprocessing as mp
import threading
from pathlib import Path
import mmap
import dolboyob

# Try to import tkinter for file dialog
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
    HAS_GUI = True
except ImportError:
    HAS_GUI = False
    print("[WARNING] tkinter not available - file dialog functionality disabled")

# ==== HARD-CODED CONFIG ========================================
# CHANGE THIS PATH TO YOUR TARGET DLL
TARGET_DLL_PATH = r"C:\Windows\System32\kernel32.dll"

WORKERS = 10                          # parallel child processes for function execution
TOTAL_DURATION_SEC = 3600             # 1 hour of runtime
MAX_ARGS_PER_CALL = 20               # 0..N args
MAX_RANDOM_BUF_BYTES = 1048576        # 1MB max buffer size for pointer args
CHILD_TIMEOUT_SEC = 2                # timeout per child process
RNG_SEED = None                      # set to an int for reproducible chaos, or None

# --- TIMING CONTROLS ---
SHUFFLE_INTERVAL_SEC = 12             # shuffle DLL/function array every 12 seconds
RANDOMIZE_INTERVAL_SEC = 13           # re-randomize parameter data every 13 seconds
EXECUTION_BATCH_SIZE = 10             # preferred batch size (but not required)

# Optional, but helps DLL dependency resolution: prepend each target DLL's dir to PATH in the child
PREPEND_DLL_DIR_TO_PATH = True

# Global data structures for function enumeration and execution
dll_function_array = []               # Array of (dll_path, function_name) tuples
current_parameter_sets = []           # Pre-generated parameter sets
last_shuffle_time = 0                # Last time we shuffled the function array
last_randomize_time = 0              # Last time we randomized parameters
target_dll_path = ""                 # Actual path to the DLL we're fuzzing

# ============================================================================

# --- minimal helpers (x64 PE parsing) ---
class PEError(Exception):
    pass

def _u16(b, o):
    return struct.unpack("<H", b[o:o+2])[0]

def _u32(b, o):
    return struct.unpack("<I", b[o:o+4])[0]

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
        pe = 0
    if hdr[pe:pe+4] != b"PE\0\0": return (False, 0, 0, 0, 0, 0)
    magic = _u16(hdr, pe + 0x18)
    if magic != 0x20b: return (False, 0, 0, 0, 0, 0)  # not PE32+
    opt_off = pe + 0x18
    opt_size = _u16(hdr, pe + 0x14)
    if opt_size < 0xF0: return (False, 0, 0, 0, 0, 0)
    num_sections = _u16(hdr, pe + 0x6)
    export_rva = _u32(hdr, opt_off + 0x70)
    export_size = _u32(hdr, opt_off + 0x74)
    return (True, export_rva, export_size, num_sections, opt_off, opt_size)

def _rva_to_off_mapped(rva, sections, data_len):
    for sec_name, sec_va, sec_vs, sec_raw, sec_rs in sections:
        if sec_va <= rva < sec_va + sec_vs:
            offset = rva - sec_va + sec_raw
            if offset < data_len:
                return offset
    return None

def parse_exports_x64_fast(path, max_names=None):
    """
    Parse x64 PE exports quickly. Returns (ok, names_list).
    If max_names is set, stop after reading that many names.
    """
    try:
        with open(path, "rb") as fp:
            is_x64, export_rva, export_size, num_sections, opt_off, opt_size = _quick_is_x64_and_has_exports(fp)
            if not is_x64 or export_rva == 0:
                return (False, [])
            
            # Read sections
            fp.seek(opt_off + opt_size, os.SEEK_SET)
            sec_data = fp.read(num_sections * 40)
            sections = []
            for i in range(num_sections):
                off = i * 40
                name = sec_data[off:off+8].rstrip(b'\0')
                vs = _u32(sec_data, off+8)
                va = _u32(sec_data, off+12)
                rs = _u32(sec_data, off+16)
                raw = _u32(sec_data, off+20)
                sections.append((name, va, vs, raw, rs))
            
            # Memory-map the file for faster access
            fp.seek(0, os.SEEK_END)
            file_size = fp.tell()
            fp.seek(0, os.SEEK_SET)
            
            with mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                export_off = _rva_to_off_mapped(export_rva, sections, file_size)
                if export_off is None:
                    return (False, [])
                
                if export_off + 40 > file_size:
                    return (False, [])
                
                # Parse export directory
                num_names = _u32(mm, export_off + 24)
                names_rva = _u32(mm, export_off + 32)
                
                if max_names and num_names > max_names:
                    num_names = max_names
                
                names_off = _rva_to_off_mapped(names_rva, sections, file_size)
                if names_off is None:
                    return (False, [])
                
                names = []
                for i in range(num_names):
                    if names_off + i*4 + 4 > file_size:
                        break
                    name_rva = _u32(mm, names_off + i*4)
                    name_off = _rva_to_off_mapped(name_rva, sections, file_size)
                    if name_off is None:
                        continue
                    
                    # Read name (find null terminator)
                    name_end = name_off
                    while name_end < file_size and mm[name_end] != 0:
                        name_end += 1
                    
                    if name_end < file_size:
                        name = mm[name_off:name_end].decode('ascii', errors='ignore')
                        if name:
                            names.append(name)
                
                return (True, names)
    except Exception:
        return (False, [])

def get_random_file_bytes(sz, files_list):
    """Get random bytes from files with enhanced dolboyob integration"""
    if not files_list:
        return os.urandom(sz)
    
    try:
        # Use dolboyob for chaos
        if random.random() < 0.3:  # 30% chance to use dolboyob
            chaos_obj = dolboyob.долбоёб()
            chaos_data = chaos_obj.хуй("dolboyob_chaos")
            if chaos_data:
                chaos_bytes = chaos_data.encode('utf-8', errors='ignore')
                if len(chaos_bytes) >= sz:
                    return chaos_bytes[:sz]
                else:
                    # Pad with random data
                    return chaos_bytes + os.urandom(sz - len(chaos_bytes))
        
        # Regular file-based random data
        file_path = random.choice(files_list)
        if os.path.isfile(file_path):
            file_size = os.path.getsize(file_path)
            if file_size > 0:
                with open(file_path, 'rb') as f:
                    offset = random.randint(0, max(0, file_size - sz))
                    f.seek(offset)
                    data = f.read(sz)
                    if len(data) == sz:
                        return data
    except:
        pass
    
    return os.urandom(sz)

def generate_randomized_input(files_list=None):
    """Generate randomized input data for function parameters"""
    input_type = random.randint(1, 25)
    
    if input_type == 1:
        # Small integer values
        return random.randint(0, 0xFFFF)
    
    elif input_type == 2:
        # Large integer values  
        return random.randint(0, 0xFFFFFFFFFFFFFFFF)
    
    elif input_type == 3:
        # Negative integers
        return random.randint(-2**31, 2**31-1)
    
    elif input_type == 4:
        # NULL pointer
        return 0
    
    elif input_type == 5:
        # Small buffer
        size = random.randint(1, 256)
        return get_random_file_bytes(size, files_list)
    
    elif input_type == 6:
        # Medium buffer
        size = random.randint(256, 4096)
        return get_random_file_bytes(size, files_list)
    
    elif input_type == 7:
        # Large buffer
        max_size = MAX_RANDOM_BUF_BYTES if MAX_RANDOM_BUF_BYTES > 0 else 1048576
        size = random.randint(4096, max_size)
        return get_random_file_bytes(size, files_list)
    
    elif input_type == 8:
        # Float values
        return random.uniform(-1e10, 1e10)
    
    elif input_type == 9:
        # String data
        length = random.randint(1, 1024)
        return get_random_file_bytes(length, files_list).decode('utf-8', errors='ignore')
    
    elif input_type == 10:
        # Binary pattern
        patterns = [b'\x00' * 32, b'\xFF' * 32, b'\xAA' * 32, b'\x55' * 32]
        return random.choice(patterns)
    
    elif input_type == 11:
        # Format strings (potential vulnerability triggers)
        format_strings = ["%s%s%s%s", "%x%x%x%x", "%n%n%n%n", "%.1000000s"]
        return random.choice(format_strings)
    
    elif input_type == 12:
        # Memory addresses (64-bit)
        bases = [0x7FFE0000, 0x400000, 0x10000000, 0x70000000]
        base = random.choice(bases)
        offset = random.randint(0, 0xFFFF)
        return base + offset
    
    elif input_type == 13:
        # File handles and special values
        special_values = [0xFFFFFFFF, 0xFFFFFFFE, 0x12345678, 0xDEADBEEF]
        return random.choice(special_values)
    
    elif input_type == 14:
        # Unicode strings
        unicode_chars = []
        for _ in range(random.randint(5, 50)):
            unicode_chars.append(chr(random.randint(0x20, 0x7E)))
        return ''.join(unicode_chars)
    
    elif input_type == 15:
        # Structured data (simulating structs)
        struct_data = struct.pack('<IIQQ', 
                                 random.randint(0, 0xFFFFFFFF),
                                 random.randint(0, 0xFFFFFFFF),
                                 random.randint(0, 0xFFFFFFFFFFFFFFFF),
                                 random.randint(0, 0xFFFFFFFFFFFFFFFF))
        return struct_data
    
    elif input_type == 16:
        # Function pointers (random addresses)
        return random.randint(0x400000, 0x7FFFFFFF) & ~0xF  # Align to 16 bytes
    
    elif input_type == 17:
        # Registry-like strings
        reg_strings = [
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows",
            "\\Registry\\Machine\\SOFTWARE\\Classes"
        ]
        return random.choice(reg_strings)
    
    elif input_type == 18:
        # Path-like strings
        paths = [
            "C:\\Windows\\System32\\kernel32.dll",
            "C:\\Program Files\\Common Files\\",
            "\\\\?\\C:\\Windows\\System32\\",
            "..\\..\\..\\Windows\\System32\\cmd.exe"
        ]
        return random.choice(paths)
    
    elif input_type == 19:
        # Time-related values
        return random.randint(0, 2**63-1)  # FILETIME values
    
    elif input_type == 20:
        # Random file content from available files
        try:
            if files_list:
                file_path = random.choice(files_list)
                chunk_size = random.randint(64, 8192)
                
                # Multiple random offsets strategy
                offsets = []
                file_size = os.path.getsize(file_path)
                for _ in range(3):
                    offsets.append(random.randint(0, max(0, file_size - chunk_size)))
                
                offset = random.choice(offsets)
                
                if offset < file_size:
                    actual_size = min(chunk_size, file_size - offset)
                    with open(file_path, 'rb') as f:
                        f.seek(offset)
                        data = f.read(actual_size)
                    return data
        except:
            pass
            
        # Fallback
        data = os.urandom(random.randint(32, 1024))
        return data
        
    elif input_type == 21:
        # Random boolean-like values
        values = [0, 1, True, False]
        value = random.choice(values)
        return value
        
    elif input_type == 22:
        # Array-like data
        element_count = random.randint(1, 16)
        elements = [random.randint(0, 0xFFFF) for _ in range(element_count)]
        array_data = struct.pack(f'<{element_count}H', *elements)
        return array_data
        
    elif input_type == 23:
        # Random string from predefined pool
        strings = [
            "tlasjfdlksjfokjaswoefjslfjape4p",
            "randomstringdata123456789",
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "1234567890!@#$%^&*()",
            "testdataforDLLexecution",
            "chaos_dll_random_string",
        ]
        string = random.choice(strings)
        return string
        
    elif input_type == 24:
        # Random small buffer (typical for many APIs)
        size = random.choice([1, 2, 4, 8, 16, 32])
        data = os.urandom(size)
        return data
        
    else:  # input_type == 25
        # Mixed/composite data
        parts = []
        for _ in range(random.randint(2, 5)):
            part_size = random.randint(4, 32)
            parts.append(os.urandom(part_size))
        data = b''.join(parts)
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

def select_dll_file():
    """Open file dialog to select a DLL file"""
    if not HAS_GUI:
        print("[-] GUI not available. Please install tkinter or manually specify DLL path.")
        return None
    
    try:
        # Create a root window and hide it
        root = tk.Tk()
        root.withdraw()
        
        # Open file dialog
        file_path = filedialog.askopenfilename(
            title="Select DLL file to fuzz",
            filetypes=[
                ("DLL files", "*.dll"),
                ("All files", "*.*")
            ]
        )
        
        root.destroy()
        return file_path if file_path else None
        
    except Exception as e:
        print(f"[-] Error opening file dialog: {e}")
        return None

def validate_dll_path(dll_path):
    """Validate that the DLL path exists and is a valid x64 PE file"""
    if not dll_path or not os.path.isfile(dll_path):
        return False
    
    try:
        # Check if it's a valid x64 PE with exports
        ok, _ = parse_exports_x64_fast(dll_path, max_names=1)
        return ok
    except:
        return False

def get_target_dll_path():
    """Get the target DLL path, with fallback to file dialog"""
    global target_dll_path
    
    # First try the hardcoded path
    if validate_dll_path(TARGET_DLL_PATH):
        target_dll_path = TARGET_DLL_PATH
        print(f"[+] Using hardcoded DLL path: {target_dll_path}")
        return target_dll_path
    
    print(f"[-] Hardcoded DLL path not found or invalid: {TARGET_DLL_PATH}")
    
    # Try to open file dialog
    selected_path = select_dll_file()
    if selected_path and validate_dll_path(selected_path):
        target_dll_path = selected_path
        print(f"[+] Using selected DLL path: {target_dll_path}")
        return target_dll_path
    
    print("[-] No valid DLL file selected or available.")
    return None

def enumerate_target_dll_functions():
    """Enumerate functions from the target DLL only"""
    global dll_function_array
    
    if not target_dll_path:
        print("[-] No target DLL path specified")
        return False
    
    print(f"[ENUMERATION] Enumerating functions from target DLL: {target_dll_path}")
    
    ok, function_names = parse_exports_x64_fast(target_dll_path)
    if not ok or not function_names:
        print(f"[-] Failed to enumerate functions from {target_dll_path}")
        return False
    
    dll_function_array = []
    for func_name in function_names:
        dll_function_array.append((target_dll_path, func_name))
    
    print(f"[ENUMERATION] Found {len(dll_function_array)} functions in target DLL")
    print(f"[ENUMERATION] Sample functions: {dll_function_array[:5]}")
    return True

def shuffle_dll_function_array():
    """Shuffle the DLL/function array every N seconds"""
    global dll_function_array, last_shuffle_time
    current_time = time.time()
    
    if current_time - last_shuffle_time >= SHUFFLE_INTERVAL_SEC:
        random.shuffle(dll_function_array)
        last_shuffle_time = current_time

def prepare_parameter_sets(files_list):
    """Prepare parameter sets for function execution"""
    global current_parameter_sets, last_randomize_time, dll_function_array
    current_time = time.time()
    
    if current_time - last_randomize_time >= RANDOMIZE_INTERVAL_SEC:
        current_parameter_sets = []
        
        # Determine how many parameter sets to prepare based on available functions and workers
        num_functions = len(dll_function_array)
        if num_functions == 0:
            # No functions available, still prepare some sets for when functions become available
            num_sets = WORKERS
        else:
            # Prepare enough sets for the available functions, but at least WORKERS sets
            num_sets = max(num_functions, WORKERS)
        
        for i in range(num_sets):
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
        print(f"[RANDOMIZE] Prepared {len(current_parameter_sets)} parameter sets for {num_functions} functions")

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
        result = fn(*args)
        return True
        
    except Exception as e:
        return False

def parallel_function_executor(files_list):
    """Execute DLL functions in parallel with timeout"""
    global dll_function_array, current_parameter_sets
    
    # Check if we have any functions to execute
    if len(dll_function_array) == 0:
        print("[WARNING] No functions enumerated - skipping execution cycle")
        return
    
    if len(current_parameter_sets) == 0:
        print("[WARNING] No parameter sets prepared - skipping execution cycle")
        return
    
    # Determine how many functions to execute this cycle
    # Use the minimum of available functions, available parameter sets, and WORKERS
    num_functions = len(dll_function_array)
    num_param_sets = len(current_parameter_sets)
    max_concurrent = min(WORKERS, num_functions, num_param_sets)
    
    # If we have more functions than we can execute concurrently, select a random subset
    if num_functions > max_concurrent:
        # Randomly select functions to execute this cycle
        selected_indices = random.sample(range(num_functions), max_concurrent)
        functions_to_execute = [dll_function_array[i] for i in selected_indices]
    else:
        # Use all available functions
        functions_to_execute = dll_function_array[:max_concurrent]
    
    # Select parameter sets (reuse if necessary)
    param_sets_to_use = []
    for i in range(len(functions_to_execute)):
        param_index = i % len(current_parameter_sets)  # Cycle through available parameter sets
        param_sets_to_use.append(current_parameter_sets[param_index])
    
    print(f"[EXEC] Executing {len(functions_to_execute)} functions with {WORKERS} max workers")
    
    # Create processes for parallel execution
    processes = []
    for i, ((dll_path, func_name), param_set) in enumerate(zip(functions_to_execute, param_sets_to_use)):
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
            proc.terminate()
            proc.join(timeout=1)
            if proc.is_alive():
                proc.kill()
            timeout_count += 1
        else:
            completed += 1
    
    execution_time = time.time() - start_time
    print(f"[EXEC] Batch complete: {completed}/{len(processes)} functions executed successfully")

def scan_random_files(root_dir):
    """Scan for random files to use as input data source"""
    files = []
    try:
        for root, dirs, filenames in os.walk(root_dir):
            # Limit depth to avoid excessive scanning
            level = root.replace(root_dir, '').count(os.sep)
            if level >= 3:
                dirs[:] = []
                continue
            
            for filename in filenames:
                if len(files) >= 1000:  # Limit number of files
                    return files
                
                filepath = os.path.join(root, filename)
                try:
                    if os.path.isfile(filepath) and os.path.getsize(filepath) > 0:
                        files.append(filepath)
                except:
                    continue
                    
    except Exception:
        pass
    
    return files

def orchestrate():
    """Main orchestration loop for single DLL fuzzing"""
    global dll_function_array, current_parameter_sets, last_shuffle_time, last_randomize_time
    
    if os.name != "nt":
        print("[-] Windows-only.", file=sys.stderr)
        sys.exit(2)
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print("[-] Use 64-bit Python to call x64 DLLs.", file=sys.stderr)
        sys.exit(2)
    if RNG_SEED is not None:
        random.seed(RNG_SEED)

    print("[STARTUP] Single DLL Fuzzer")
    print(f"[CONFIG] Target DLL: {TARGET_DLL_PATH}")
    print(f"[CONFIG] Workers: {WORKERS}, Duration: {TOTAL_DURATION_SEC}s")
    
    # Get the target DLL path
    if not get_target_dll_path():
        print("[-] No valid target DLL available. Exiting.")
        sys.exit(1)
    
    # Enumerate functions from target DLL
    if not enumerate_target_dll_functions():
        print("[-] Failed to enumerate DLL functions. Exiting.")
        sys.exit(1)
    
    # Get files for random data (using the DLL's directory)
    dll_dir = os.path.dirname(target_dll_path)
    files = scan_random_files(dll_dir)
    if not files:
        # Fallback to system directory
        files = scan_random_files(r"C:\Windows\System32")
    if not files:
        print("[!] No files found for random data; using fallback methods.")
    else:
        print(f"[+] Found {len(files)} files for random data generation")
    
    # Initialize timing
    last_shuffle_time = time.time()
    last_randomize_time = time.time()
    
    # Prepare initial parameter sets
    prepare_parameter_sets(files)
    
    print(f"[READY] Starting DLL fuzzing loop for {TOTAL_DURATION_SEC} seconds...")
    
    start_time = time.time()
    execution_cycle = 0
    
    while time.time() - start_time < TOTAL_DURATION_SEC:
        execution_cycle += 1
        cycle_start = time.time()
        
        # 1. Shuffle function array if needed
        shuffle_dll_function_array()
        
        # 2. Prepare new parameter sets if needed
        prepare_parameter_sets(files)
        
        # 3. Execute functions in parallel
        parallel_function_executor(files)
        
        cycle_time = time.time() - cycle_start
        elapsed_total = time.time() - start_time
        
        if execution_cycle % 10 == 0:
            print(f"[PROGRESS] Cycle {execution_cycle}, Elapsed: {elapsed_total:.1f}s/{TOTAL_DURATION_SEC}s")
        
        # Brief pause before next cycle
        time.sleep(0.01)

def main():
    mp.freeze_support()
    mp.set_start_method("spawn", force=True)
    try:
        orchestrate()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[ERROR] {e}")
    print("[+] Done.")

if __name__ == "__main__":
    main()