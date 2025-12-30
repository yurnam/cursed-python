#!/usr/bin/env python3
# DLL Fuzzer - scans System32 and fuzzes random DLLs sequentially
#
# Features:
# - Scans all DLLs in C:\Windows\System32
# - Picks a random DLL, fuzzes it for ~20 seconds
# - Then picks another, and so on
# - Workers load DLL once and execute many functions
# - Parent respawns crashed workers

import os
import sys
import struct
import random
import time
import ctypes
import multiprocessing as mp
from pathlib import Path
import mmap

# ==== HARD-CODED CONFIG ========================================
WORKERS = 10  # parallel processes for function execution
TOTAL_DURATION_SEC = 36009  # total runtime
FUZZ_PER_DLL_SEC = 2  # fuzz each DLL for ~20 seconds
MAX_ARGS_PER_CALL = 6  # 0..N args
MAX_RANDOM_BUF_BYTES = 3048576  # 1MB max buffer size for pointer args
RNG_SEED = None  # set to an int for reproducible chaos, or None
WORKER_TIMEOUT_SEC = 10  # timeout to check and respawn workers

# --- TIMING CONTROLS ---
SHUFFLE_INTERVAL_SEC = 3  # shuffle function array every 12 seconds
RANDOMIZE_INTERVAL_SEC = 2  # re-randomize parameter data every 13 seconds
EXECUTION_BATCH_SIZE = 3  # preferred batch size (but not required)

# Optional, but helps DLL dependency resolution: prepend DLL's dir to PATH
PREPEND_DLL_DIR_TO_PATH = True

SYSTEM32_DIR = r"C:\Windows\System32"


# ============================================================================

# --- minimal helpers (x64 PE parsing) ---
class PEError(Exception):
    pass


def _u16(b, o):
    return struct.unpack("<H", b[o:o + 2])[0]


def _u32(b, o):
    return struct.unpack("<I", b[o:o + 4])[0]


def _quick_is_x64_and_has_exports(fp):
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
    if hdr[pe:pe + 4] != b"PE\0\0": return (False, 0, 0, 0, 0, 0)
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
                name = sec_data[off:off + 8].rstrip(b'\0')
                vs = _u32(sec_data, off + 8)
                va = _u32(sec_data, off + 12)
                rs = _u32(sec_data, off + 16)
                raw = _u32(sec_data, off + 20)
                sections.append((name, va, vs, raw, rs))

            # Memory-map the file
            fp.seek(0, os.SEEK_END)
            file_size = fp.tell()
            fp.seek(0, os.SEEK_SET)

            with mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                export_off = _rva_to_off_mapped(export_rva, sections, file_size)
                if export_off is None:
                    return (False, [])

                if export_off + 40 > file_size:
                    return (False, [])

                num_names = _u32(mm, export_off + 24)
                names_rva = _u32(mm, export_off + 32)

                if max_names and num_names > max_names:
                    num_names = max_names

                names_off = _rva_to_off_mapped(names_rva, sections, file_size)
                if names_off is None:
                    return (False, [])

                names = []
                for i in range(num_names):
                    if names_off + i * 4 + 4 > file_size:
                        break
                    name_rva = _u32(mm, names_off + i * 4)
                    name_off = _rva_to_off_mapped(name_rva, sections, file_size)
                    if name_off is None:
                        continue

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
    if not files_list:
        return os.urandom(sz)

    try:
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
    input_type = random.randint(1, 25)

    if input_type == 1:
        return random.randint(0, 0xFFFF)

    elif input_type == 2:
        return random.randint(0, 0xFFFFFFFFFFFFFFFF)

    elif input_type == 3:
        return random.randint(-2 ** 31, 2 ** 31 - 1)

    elif input_type == 4:
        return 0

    elif input_type == 5:
        size = random.randint(1, 256)
        return get_random_file_bytes(size, files_list)

    elif input_type == 6:
        size = random.randint(256, 4096)
        return get_random_file_bytes(size, files_list)

    elif input_type == 7:
        max_size = MAX_RANDOM_BUF_BYTES if MAX_RANDOM_BUF_BYTES > 0 else 1048576
        size = random.randint(4096, max_size)
        return get_random_file_bytes(size, files_list)

    elif input_type == 8:
        return random.uniform(-1e10, 1e10)

    elif input_type == 9:
        length = random.randint(1, 1024)
        return get_random_file_bytes(length, files_list).decode('utf-8', errors='ignore')

    elif input_type == 10:
        patterns = [b'\x00' * 32, b'\xFF' * 32, b'\xAA' * 32, b'\x55' * 32]
        return random.choice(patterns)

    elif input_type == 11:
        format_strings = ["%s%s%s%s", "%x%x%x%x", "%n%n%n%n", "%.1000000s"]
        return random.choice(format_strings)

    elif input_type == 12:
        bases = [0x7FFE0000, 0x400000, 0x10000000, 0x70000000]
        base = random.choice(bases)
        offset = random.randint(0, 0xFFFF)
        return base + offset

    elif input_type == 13:
        special_values = [0xFFFFFFFF, 0xFFFFFFFE, 0x12345678, 0xDEADBEEF]
        return random.choice(special_values)

    elif input_type == 14:
        unicode_chars = []
        for _ in range(random.randint(5, 50)):
            unicode_chars.append(chr(random.randint(0x20, 0x7E)))
        return ''.join(unicode_chars)

    elif input_type == 15:
        struct_data = struct.pack('<IIQQ',
                                  random.randint(0, 0xFFFFFFFF),
                                  random.randint(0, 0xFFFFFFFF),
                                  random.randint(0, 0xFFFFFFFFFFFFFFFF),
                                  random.randint(0, 0xFFFFFFFFFFFFFFFF))
        return struct_data

    elif input_type == 16:
        return random.randint(0x400000, 0x7FFFFFFF) & ~0xF

    elif input_type == 17:
        reg_strings = [
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows",
            "\\Registry\\Machine\\SOFTWARE\\Classes"
        ]
        return random.choice(reg_strings)

    elif input_type == 18:
        paths = [
            "C:\\Windows\\System32\\kernel32.dll",
            "C:\\Program Files\\Common Files\\",
            "\\\\?\\C:\\Windows\\System32\\",
            "..\\..\\..\\Windows\\System32\\cmd.exe"
        ]
        return random.choice(paths)

    elif input_type == 19:
        return random.randint(0, 2 ** 63 - 1)

    elif input_type == 20:
        try:
            if files_list:
                file_path = random.choice(files_list)
                chunk_size = random.randint(64, 8192)

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

        data = os.urandom(random.randint(32, 1024))
        return data

    elif input_type == 21:
        values = [0, 1, True, False]
        value = random.choice(values)
        return value

    elif input_type == 22:
        element_count = random.randint(1, 16)
        elements = [random.randint(0, 0xFFFF) for _ in range(element_count)]
        array_data = struct.pack(f'<{element_count}H', *elements)
        return array_data

    elif input_type == 23:
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
        size = random.choice([1, 2, 4, 8, 16, 32])
        data = os.urandom(size)
        return data

    else:  # input_type == 25
        parts = []
        for _ in range(random.randint(2, 5)):
            part_size = random.randint(4, 32)
            parts.append(os.urandom(part_size))
        data = b''.join(parts)
        return data


def convert_to_ctypes(input_data):
    if isinstance(input_data, bytes):
        if len(input_data) > 0:
            return ctypes.create_string_buffer(input_data)
        else:
            return ctypes.c_void_p(0)
    elif isinstance(input_data, str):
        try:
            return ctypes.c_char_p(input_data.encode('utf-8', errors='ignore'))
        except:
            return ctypes.c_void_p(0)
    elif isinstance(input_data, int):
        if -2 ** 31 <= input_data <= 2 ** 31 - 1:
            return ctypes.c_int(input_data)
        elif 0 <= input_data <= 2 ** 32 - 1:
            return ctypes.c_uint32(input_data)
        elif 0 <= input_data <= 2 ** 64 - 1:
            return ctypes.c_uint64(input_data)
        else:
            return ctypes.c_void_p(input_data & 0xFFFFFFFFFFFFFFFF)
    elif isinstance(input_data, float):
        return ctypes.c_double(input_data)
    elif isinstance(input_data, bool):
        return ctypes.c_bool(input_data)
    else:
        return ctypes.c_void_p(random.randint(0, 0xFFFFFFFF))


def scan_system32_dlls():
    dlls = []
    for root, dirs, files in os.walk(SYSTEM32_DIR):
        for file in files:
            if file.lower().endswith('.dll'):
                dlls.append(os.path.join(root, file))
    return dlls


def enumerate_target_dll_functions(target_dll_path):
    print(f"[ENUMERATION] Enumerating functions from target DLL: {target_dll_path}")

    ok, function_names = parse_exports_x64_fast(target_dll_path)
    if not ok or not function_names:
        print(f"[-] Failed to enumerate functions from {target_dll_path}")
        return []

    print(f"[ENUMERATION] Found {len(function_names)} functions in target DLL")
    print(f"[ENUMERATION] Sample functions: {function_names[:5]}")
    return function_names


def load_dll(target_dll_path):
    path = Path(target_dll_path)
    if PREPEND_DLL_DIR_TO_PATH:
        os.environ["PATH"] = str(path.parent) + os.pathsep + os.environ.get("PATH", "")

    try:
        dll = ctypes.WinDLL(target_dll_path)
        print(f"[+] Successfully loaded DLL: {target_dll_path}")
        return dll
    except Exception as e:
        print(f"[-] Failed to load DLL: {e}")
        return None


def worker_process(target_dll_path, dll_function_array, files_list):
    # Load DLL once in this process
    lib = load_dll(target_dll_path)
    if not lib:
        return

    # Local result pool for this worker
    result_pool = []

    while True:
        # Shuffle locally
        random.shuffle(dll_function_array)

        # Prepare parameter sets
        current_parameter_sets = []
        num_functions = len(dll_function_array)
        num_sets = max(num_functions, EXECUTION_BATCH_SIZE)

        for i in range(num_sets):
            num_args = random.randint(0, MAX_ARGS_PER_CALL)
            param_set = []

            for j in range(num_args):
                try:
                    if random.random() < 0.5 and result_pool:
                        param_data = random.choice(result_pool)
                    else:
                        param_data = generate_randomized_input(files_list)
                    param_set.append(param_data)
                except Exception:
                    param_set.append(random.randint(0, 0xFFFFFFFF))

            current_parameter_sets.append(param_set)

        # Execute many functions
        num_exec = min(EXECUTION_BATCH_SIZE, num_functions, len(current_parameter_sets))

        if num_functions > num_exec:
            selected_indices = random.sample(range(num_functions), num_exec)
            functions_to_execute = [dll_function_array[i] for i in selected_indices]
        else:
            functions_to_execute = dll_function_array[:num_exec]

        param_sets_to_use = []
        for i in range(len(functions_to_execute)):
            param_index = i % len(current_parameter_sets)
            param_sets_to_use.append(current_parameter_sets[param_index])

        for func_name, param_set in zip(functions_to_execute, param_sets_to_use):
            if "LockWorks" in func_name:
                continue
            try:
                random.seed(random.getrandbits(32))

                fn = getattr(lib, func_name)
                fn.restype = random.choice([ctypes.c_uint64, ctypes.c_int, ctypes.c_double, ctypes.c_void_p, None])

                args = []
                for param_data in param_set:
                    try:
                        converted_arg = convert_to_ctypes(param_data)
                        args.append(converted_arg)
                    except Exception:
                        args.append(ctypes.c_void_p(0))

                result = fn(*args)

                if result is not None:
                    result_pool.append(result)

            except Exception as e:
                pass

        time.sleep(0.01)


def scan_random_files(root_dir):
    files = []
    try:
        for root, dirs, filenames in os.walk(root_dir):
            level = root.replace(root_dir, '').count(os.sep)
            if level >= 3:
                dirs[:] = []
                continue

            for filename in filenames:
                if len(files) >= 1000:
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
    if os.name != "nt":
        print("[-] Windows-only.", file=sys.stderr)
        sys.exit(2)
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print("[-] Use 64-bit Python to call x64 DLLs.", file=sys.stderr)
        sys.exit(2)
    if RNG_SEED is not None:
        random.seed(RNG_SEED)

    print("[STARTUP] System32 DLL Fuzzer")

    system32_dlls = scan_system32_dlls()
    if not system32_dlls:
        print("[-] No DLLs found in System32. Exiting.")
        sys.exit(1)
    print(f"[+] Found {len(system32_dlls)} DLLs in System32")

    files = scan_random_files(SYSTEM32_DIR)
    if not files:
        print("[!] No files found for random data; using fallback methods.")
    else:
        print(f"[+] Found {len(files)} files for random data generation")

    print(f"[READY] Starting DLL fuzzing loop for {TOTAL_DURATION_SEC} seconds...")

    start_time = time.time()

    while time.time() - start_time < TOTAL_DURATION_SEC:
        # Pick random DLL
        target_dll_path = random.choice(system32_dlls)
        print(f"[+] Selected DLL to fuzz: {target_dll_path}")

        dll_function_array = enumerate_target_dll_functions(target_dll_path)
        if not dll_function_array:
            continue

        processes = []
        fuzz_start = time.time()

        # Start workers for this DLL
        for i in range(WORKERS):
            p = mp.Process(target=worker_process, args=(target_dll_path, dll_function_array, files), daemon=True)
            p.start()
            processes.append(p)

        # Fuzz for FUZZ_PER_DLL_SEC seconds, managing workers
        while time.time() - fuzz_start < FUZZ_PER_DLL_SEC:
            time.sleep(WORKER_TIMEOUT_SEC)

            # Check and respawn dead workers
            new_processes = []
            for p in processes:
                if p.is_alive():
                    new_processes.append(p)
                else:
                    print(f"[ORCHESTRATOR] Worker died, respawning...")
                    np = mp.Process(target=worker_process, args=(target_dll_path, dll_function_array, files),
                                    daemon=True)
                    np.start()
                    new_processes.append(np)

            # Maintain WORKERS count
            while len(new_processes) < WORKERS:
                p = mp.Process(target=worker_process, args=(target_dll_path, dll_function_array, files), daemon=True)
                p.start()
                new_processes.append(p)

            processes = new_processes

        # Kill workers for this DLL
        for p in processes:
            if p.is_alive():
                p.terminate()

        print(f"[+] Finished fuzzing {target_dll_path} for {FUZZ_PER_DLL_SEC} seconds")

    print("[+] Total time limit reached. Exiting.")


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