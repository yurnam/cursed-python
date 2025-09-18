#!/usr/bin/env python3
# acc — the "Windows chaos compiler"
# Usage: ./acc [file] -> uses all file bytes for chaotic x86-64 code
#        ./acc -> uses os.urandom
# Produces ./a.exe: PE64 x86-64 binary for Windows
import os, sys, struct
PAGE = 0x1000
BASE_VADDR = 0x400000
PE_HDR = 0x200  # Enough for DOS, PE, optional header, and section table
SECTION_VADDR = BASE_VADDR + PAGE
def pad_to_multiple(b: bytes, mult: int, min_len: int) -> bytes:
    if len(b) < min_len:
        b += os.urandom(min_len - len(b))
    r = len(b) % mult
    if r:
        b += os.urandom(mult - r)
    return b
def s32(x): return struct.pack("<I", x)
def s64(x): return struct.pack("<Q", x)
def generate_chaotic_code(input_bytes: bytes) -> bytes:
    code = bytearray()
    loop_top = len(code)
    # Initialize registers
    for i in range(0, min(8, len(input_bytes))):
        val = input_bytes[i] if i < len(input_bytes) else 0
        reg = [b"\x48\xC7\xC0", b"\x48\xC7\xC3", b"\x48\xC7\xC1", b"\x48\xC7\xC2"][i % 4]
        code += reg + bytes([val, 0, 0, 0])
    # Allocate 8KB stack buffer
    code += b"\x48\x81\xEC\x00\x20\x00\x00"  # sub rsp, 0x2000
    code += b"\x48\x89\xE3"  # mov rbx, rsp
    # Resolve GetStdHandle and WriteConsoleA addresses (placeholders)
    code += b"\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"  # mov rax, GetStdHandle
    code += b"\x48\x83\xEC\x20"  # sub rsp, 32 (shadow space)
    code += b"\x48\xC7\xC1\xF5\xFF\xFF\xFF"  # mov rcx, -11 (STD_OUTPUT_HANDLE)
    code += b"\xFF\xD0"  # call rax
    code += b"\x48\x83\xC4\x20"  # add rsp, 32
    code += b"\x48\x89\xC7"  # mov rdi, rax (stdout handle)
    code += b"\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"  # mov rax, WriteConsoleA
    # Main loop
    for i in range(0, len(input_bytes), 4):
        chunk = input_bytes[i:i+4]
        op = chunk[0] % 6 if len(chunk) > 0 else 0
        val = int.from_bytes(chunk, "little") % 0x1000 if len(chunk) > 0 else 0
        # Reset rbx every 32 iterations
        if i % 32 == 0:
            code += b"\x48\x89\xE3"  # mov rbx, rsp
        if op == 0:
            code += b"\x48\x05" + s32(val)  # add rax, <val>
        elif op == 1:
            code += b"\x48\x81\xF3" + s32(val)  # xor rbx, <val>
        elif op == 2:
            code += b"\x48\x81\xE9" + s32(val)  # sub rcx, <val>
        elif op == 3:
            code += b"\x48\x89\x03"  # mov [rbx], rax
            code += b"\x48\x83\xC3\x08"  # add rbx, 8
        elif op == 4:
            # WriteConsoleA(handle, buffer, length, written, reserved)
            code += b"\x48\x83\xEC\x20"  # sub rsp, 32 (shadow space)
            code += b"\x48\x89\xF9"  # mov rcx, rdi (stdout handle)
            code += b"\x48\x89\xDA"  # mov rdx, rbx (buffer)
            code += b"\x48\xC7\xC0\x08\x00\x00\x00"  # mov rax, 8 (length)
            code += b"\x4C\x8D\x4C\x24\x1C"  # lea r9, [rsp+28] (written)
            code += b"\x48\xC7\xC6\x00\x00\x00\x00"  # mov rsi, 0 (reserved)
            code += b"\x48\x8B\x3D\xC3\xFF\xFF\xFF"  # mov rdi, [rip-61] (WriteConsoleA)
            code += b"\xFF\xD7"  # call rdi
            code += b"\x48\x83\xC4\x20"  # add rsp, 32
            code += b"\x48\x89\xF8"  # mov rax, rdi (restore rax)
            code += b"\x48\x8B\x3D\xB5\xFF\xFF\xFF"  # mov rdi, [rip-75] (restore stdout handle)
        elif op == 5:
            # Sleep(100ms) for pacing
            code += b"\x48\x83\xEC\x20"  # sub rsp, 32
            code += b"\x48\xC7\xC1\x64\x00\x00\x00"  # mov rcx, 100
            code += b"\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"  # mov rax, Sleep
            code += b"\xFF\xD0"  # call rax
            code += b"\x48\x83\xC4\x20"  # add rsp, 32
    # Absolute jump to loop_top
    code += b"\x48\xB8" + s64(SECTION_VADDR)  # mov rax, SECTION_VADDR
    code += b"\xFF\xE0"  # jmp rax
    return bytes(code)
def build_pe_binary(arg_blob: bytes, code_off: int = PAGE) -> bytes:
    code = generate_chaotic_code(arg_blob)
    # DOS header
    dos_hdr = b"MZ" + b"\x00" * 58 + s32(0x80)  # e_lfanew at offset 60
    dos_hdr = dos_hdr.ljust(0x80, b"\x00")
    # PE signature and file header
    pe_hdr = b"PE\x00\x00" + struct.pack("<HHIIIHH",
        0x8664,  # Machine (x86-64)
        1,       # NumberOfSections
        0,       # TimeDateStamp
        0,       # PointerToSymbolTable
        0,       # NumberOfSymbols
        0xE0,    # SizeOfOptionalHeader
        0x2E)    # Characteristics (executable, large address aware)
    # Optional header (PE32+)
    opt_hdr = struct.pack("<HBBIIIIQQQQIIQQ",
        0x20B,   # Magic (PE32+)
        0, 0,    # Linker version
        len(code),  # SizeOfCode
        0,       # SizeOfInitializedData
        0,       # SizeOfUninitializedData
        code_off,  # AddressOfEntryPoint
        code_off,  # BaseOfCode
        BASE_VADDR,  # ImageBase
        PAGE,    # SectionAlignment
        PAGE,    # FileAlignment
        6, 0,    # OS version
        0, 0,    # Image version
        6, 0,    # Subsystem version
        0,       # Win32VersionValue
        len(code) + code_off,  # SizeOfImage
        0x200,   # SizeOfHeaders
        0,       # CheckSum
        3,       # Subsystem (console)
        0)       # DllCharacteristics
    # Data directories (16 entries, all zero)
    opt_hdr += b"\x00" * (16 * 8)
    # Section table
    section_hdr = struct.pack("<8sIIIIIIHHI",
        b".text\x00\x00\x00",  # Name
        len(code),  # VirtualSize
        code_off,   # VirtualAddress
        len(code),  # SizeOfRawData
        code_off,   # PointerToRawData
        0,         # PointerToRelocations
        0,         # PointerToLinenumbers
        0,         # NumberOfRelocations
        0,         # NumberOfLinenumbers
        0x60000020)  # Characteristics (code, executable, readable)
    pe = dos_hdr + pe_hdr + opt_hdr + section_hdr
    pe = pe.ljust(code_off, b"\x00")
    blob = bytes(pe) + code
    return blob
def main():
    source_path = sys.argv[1] if len(sys.argv) >= 2 else None
    if source_path:
        try:
            with open(source_path, "rb") as f:
                data = f.read()  # Use all bytes
            if not data:
                raise ValueError("Input file is empty.")
            print(f"[+] using {source_path} (all {len(data)} bytes)")
        except Exception as e:
            print(f"[-] failed to read {source_path}: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        data = os.urandom(8 * 1024)
        print(f"[+] using os.urandom ({len(data)} bytes)")
    pe = build_pe_binary(data, code_off=PAGE)
    out = "a.exe"
    with open(out, "wb") as f:
        f.write(pe)
    os.chmod(out, 0o755) if os.name != "nt" else None
    print(f"[+] wrote {out} size={len(pe)} bytes")
    print(f"[+] entry @ 0x{BASE_VADDR + PAGE:016x}")
    print("[!] WARNING: Binary runs chaotic but valid code. Use in a VM!")
    print(" Expect console spam, CPU usage, or hangs.")
if __name__ == "__main__":
    main()
