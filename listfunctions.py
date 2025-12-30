#!/usr/bin/env python3
# Script to load a hardcoded DLL and save a list of all exported functions to a file

import os
import sys
import struct
import ctypes
from pathlib import Path
import mmap

# Hardcoded DLL path (change this to your target DLL)
HARDCODED_DLL_PATH = r"C:\Windows\System32\user32.dll"

# Output file for the list of functions
OUTPUT_FILE = "exported_functions.txt"


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


def get_exported_functions(dll_path):
    try:
        with open(dll_path, "rb") as fp:
            is_x64, export_rva, export_size, num_sections, opt_off, opt_size = _quick_is_x64_and_has_exports(fp)
            if not is_x64 or export_rva == 0:
                return []

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
                    return []

                if export_off + 40 > file_size:
                    return []

                num_names = _u32(mm, export_off + 24)
                names_rva = _u32(mm, export_off + 32)

                names_off = _rva_to_off_mapped(names_rva, sections, file_size)
                if names_off is None:
                    return []

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

                return names
    except Exception as e:
        print(f"Error parsing DLL: {e}")
        return []


def main():
    if os.name != "nt":
        print("[-] Windows-only.")
        sys.exit(2)
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print("[-] Use 64-bit Python.")
        sys.exit(2)

    print(f"[+] Loading DLL: {HARDCODED_DLL_PATH}")
    functions = get_exported_functions(HARDCODED_DLL_PATH)

    if not functions:
        print("[-] No functions found or error loading DLL.")
        sys.exit(1)

    print(f"[+] Found {len(functions)} exported functions.")

    # Save to file
    with open(OUTPUT_FILE, 'w') as f:
        for func in sorted(functions):
            f.write(f"{func}\n")

    print(f"[+] Saved function list to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()