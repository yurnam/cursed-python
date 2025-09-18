#!/usr/bin/env python3
# acc — the "chaos compiler" for Windows (PE32+ x86-64)
# Usage: ./acc_win.py [file] -> uses all file bytes for chaotic code
#        ./acc_win.py         -> uses /dev/urandom
# Produces ./a.exe: PE32+ console binary (x86-64)

import os, sys, struct

# --- PE/section layout constants ---
IMAGE_BASE = 0x140000000
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200
TEXT_RVA = 0x1000
IDATA_RVA = 0x2000

def align_up(x, a): return ( (x + a - 1) // a ) * a
def s32(x): return struct.pack("<i", x)
def u16(x): return struct.pack("<H", x)
def u32(x): return struct.pack("<I", x)
def u64(x): return struct.pack("<Q", x)

def build_idata():
    """
    Build a minimal import table for:
        KERNEL32.dll: GetStdHandle, WriteFile, ExitProcess, Sleep
    Returns (idata_bytes, info_dict).
    """
    funcs = ["GetStdHandle", "WriteFile", "ExitProcess", "Sleep"]
    content = bytearray()

    # Reserve space for two IMAGE_IMPORT_DESCRIPTORs (one real + null)
    desc_off = 0
    content += b"\x00" * 40

    # ILT (OriginalFirstThunk)
    ilt_off = len(content)
    content += b"\x00" * (8 * (len(funcs) + 1))

    # IAT (FirstThunk)
    iat_off = len(content)
    content += b"\x00" * (8 * (len(funcs) + 1))

    # DLL name
    dll_name = b"KERNEL32.dll\x00"
    dll_name_off = len(content)
    content += dll_name
    if len(content) & 1: content += b"\x00"  # 2-byte align for hints

    # Hint/Name entries
    hn_offs = {}
    for fn in funcs:
        off = len(content)
        hn_offs[fn] = off
        content += u16(0) + fn.encode('ascii') + b"\x00"
        if len(content) & 1: content += b"\x00"

    # Fill ILT and IAT with RVA to Hint/Name entries
    for i, fn in enumerate(funcs):
        rva_hn = IDATA_RVA + hn_offs[fn]
        content[ilt_off + i*8: ilt_off + (i+1)*8] = u64(rva_hn)
        content[iat_off + i*8: iat_off + (i+1)*8] = u64(rva_hn)

    # Fill real IMAGE_IMPORT_DESCRIPTOR
    imp_desc = struct.pack("<IIIII",
        IDATA_RVA + ilt_off,        # OriginalFirstThunk (ILT)
        0,                          # TimeDateStamp
        0,                          # ForwarderChain
        IDATA_RVA + dll_name_off,   # Name
        IDATA_RVA + iat_off         # FirstThunk (IAT)
    )
    content[desc_off:desc_off+20] = imp_desc  # null-terminator desc already zero

    info = {
        'IAT_RVA':             IDATA_RVA + iat_off,
        'GetStdHandle_IAT_RVA':IDATA_RVA + iat_off + 0*8,
        'WriteFile_IAT_RVA':   IDATA_RVA + iat_off + 1*8,
        'ExitProcess_IAT_RVA': IDATA_RVA + iat_off + 2*8,
        'Sleep_IAT_RVA':       IDATA_RVA + iat_off + 3*8,
    }
    return bytes(content), info

def generate_chaotic_code_windows(input_bytes: bytes):
    """
    Emit x86-64 code that:
      - Reserves 4 KiB on stack (RBX points to it)
      - Grabs stdout handle via GetStdHandle(-11) into R12
      - Loops over input bytes to do chaotic ops; op==4 -> WriteFile(h, RBX, 8, &written, NULL)
      - op==5 -> Sleep(1) to occasionally yield
    Returns (code_bytes, patch_sites), where patch_sites are 'call [rip+rel32]' to fill.
    """
    code = bytearray()
    patch_sites = []  # items: (pos, "GetStdHandle"/"WriteFile"/"Sleep"/"ExitProcess")

    def call_iat(tag):
        pos = len(code)
        code.extend(b"\xFF\x15\x00\x00\x00\x00")  # call qword [rip+rel32]
        patch_sites.append((pos, tag))

    # Initialize a few regs from data (like original)
    for i in range(0, min(8, len(input_bytes))):
        val = input_bytes[i]
        reg = [b"\x48\xC7\xC0", b"\x48\xC7\xC3", b"\x48\xC7\xC1", b"\x48\xC7\xC2"][i % 4]  # mov rAX/rBX/rCX/rDX, imm32
        code += reg + bytes([val, 0, 0, 0])

    # Reserve 4KiB and set RBX = RSP (our buffer)
    code += b"\x48\x81\xEC\x00\x10\x00\x00"   # sub rsp, 0x1000
    code += b"\x48\x89\xE3"                   # mov rbx, rsp

    # GetStdHandle(STD_OUTPUT_HANDLE = -11) -> RAX, save in R12
    code += b"\x48\x83\xEC\x28"               # sub rsp, 0x28 (shadow+align)
    code += b"\x48\xB9" + struct.pack("<Q", 0xFFFFFFFFFFFFFFF5)  # mov rcx, -11 (imm64)
    call_iat('GetStdHandle')
    code += b"\x48\x83\xC4\x28"               # add rsp, 0x28
    code += b"\x49\x89\xC4"                   # mov r12, rax

    loop_top = len(code)

    # Main chaotic loop
    for i in range(0, len(input_bytes), 4):
        chunk = input_bytes[i:i+4]
        op = chunk[0] % 6 if chunk else 0
        val = int.from_bytes(chunk, "little") % 0x1000 if chunk else 0

        # keep RBX inside our 4KiB every ~256 iterations
        if i % 256 == 0:
            code += b"\x48\x89\xE3"           # mov rbx, rsp

        if op == 0:
            code += b"\x48\x05" + s32(val)    # add rax, imm32
        elif op == 1:
            code += b"\x48\x81\xF3" + s32(val)# xor rbx, imm32
        elif op == 2:
            code += b"\x48\x81\xE9" + s32(val)# sub rcx, imm32
        elif op == 3:
            code += b"\x48\x89\x03"           # mov [rbx], rax
            code += b"\x48\x83\xC3\x08"       # add rbx, 8
        elif op == 4:
            # WriteFile(h=R12, buf=RBX, 8, &written, NULL)
            # Windows x64 ABI: RCX,RDX,R8,R9 + 32-byte shadow space, keep 16B alignment
            code += b"\x48\x83\xEC\x38"       # sub rsp, 0x38 (shadow 0x20 + args + align)
            code += b"\x4C\x89\xE1"           # mov rcx, r12
            code += b"\x48\x89\xDA"           # mov rdx, rbx
            code += b"\x41\xB8\x08\x00\x00\x00"      # mov r8d, 8
            code += b"\x4C\x8D\x4C\x24\x28"          # lea r9, [rsp+0x28]  ; LPDWORD written
            code += b"\x48\xC7\x44\x24\x20\x00\x00\x00\x00"  # [rsp+0x20] = NULL (LPOVERLAPPED)
            call_iat('WriteFile')
            code += b"\x48\x83\xC4\x38"       # add rsp, 0x38
        elif op == 5:
            # Sleep(1) to yield a bit
            code += b"\x48\x83\xEC\x28"       # sub rsp, 0x28
            code += b"\xB9\x01\x00\x00\x00"   # mov ecx, 1
            call_iat('Sleep')
            code += b"\x48\x83\xC4\x28"       # add rsp, 0x28

    # jmp back to loop_top
    off_jmp = len(code)
    code += b"\xE9\x00\x00\x00\x00"
    code_va = IMAGE_BASE + TEXT_RVA
    rip_after = code_va + off_jmp + 5
    rel = (code_va + loop_top) - rip_after
    code[off_jmp+1:off_jmp+5] = s32(rel)

    return bytes(code), patch_sites

def build_pe_exe(code: bytes, idata_bytes: bytes, idata_info: dict, patches):
    # Patch all 'call [rip+rel32]' sites to point at the IAT entries
    code = bytearray(code)
    text_va = IMAGE_BASE + TEXT_RVA
    tag_to_rva = {
        'GetStdHandle': idata_info['GetStdHandle_IAT_RVA'],
        'WriteFile':    idata_info['WriteFile_IAT_RVA'],
        'ExitProcess':  idata_info['ExitProcess_IAT_RVA'],
        'Sleep':        idata_info['Sleep_IAT_RVA'],
    }
    for pos, tag in patches:
        target = IMAGE_BASE + tag_to_rva[tag]
        rip_after = text_va + pos + 6  # after 'FF 15 <disp32>'
        disp = target - rip_after
        code[pos+2:pos+6] = s32(disp)
    code = bytes(code)

    # --- Build PE headers ---
    nsections = 2  # .text, .idata

    # DOS header (64 bytes) with e_lfanew -> 0x80
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[60:64] = u32(0x80)

    headers = bytearray()
    headers += dos
    headers += b"\x00" * (0x80 - len(headers))
    headers += b"PE\x00\x00"  # NT signature

    # COFF File Header
    Machine = 0x8664
    SizeOfOptionalHeader = 240  # PE32+
    Characteristics = 0x0022     # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    coff = struct.pack("<HHIIIHH",
        Machine, nsections, 0, 0, 0,
        SizeOfOptionalHeader, Characteristics
    )
    headers += coff

    # Optional Header (PE32+)
    SizeOfCode = align_up(len(code), FILE_ALIGNMENT)
    SizeOfInitData = align_up(len(idata_bytes), FILE_ALIGNMENT)
    AddressOfEntryPoint = TEXT_RVA
    BaseOfCode = TEXT_RVA
    SizeOfImage = align_up(IDATA_RVA + len(idata_bytes), SECTION_ALIGNMENT)
    SizeOfHeaders = align_up(0x80 + 4 + 20 + SizeOfOptionalHeader + (nsections*40), FILE_ALIGNMENT)

    opt_fmt = "<HBBIII" "IIQII" "HHHHHH" "IIIIHH" "QQQQII"
    opt = struct.pack(opt_fmt,
        0x20B,             # Magic (PE32+)
        14, 0,             # Linker version
        SizeOfCode, SizeOfInitData, 0,
        AddressOfEntryPoint, BaseOfCode,
        IMAGE_BASE, SECTION_ALIGNMENT, FILE_ALIGNMENT,
        6, 0,              # OS version 6.0
        0, 0,              # Image version
        6, 0,              # Subsystem version 6.0
        0,                 # Win32VersionValue
        SizeOfImage, SizeOfHeaders,
        0,                 # CheckSum (let OS compute)
        3,                 # Subsystem: WINDOWS_CUI
        0x0000,            # DllCharacteristics (no ASLR)
        0x00100000, 0x00001000,   # Stack reserve/commit
        0x00100000, 0x00001000,   # Heap reserve/commit
        0, 16             # LoaderFlags, NumberOfRvaAndSizes
    )
    headers += opt

    # Data directories (16 entries)
    dd = [ (0,0) ] * 16
    dd[1]  = (IDATA_RVA, len(idata_bytes))            # Import Directory
    dd[12] = (idata_info['IAT_RVA'], 8*(4+1))         # IAT
    for rva, sz in dd:
        headers += struct.pack("<II", rva, sz)

    # Section headers
    text_raw_ptr  = SizeOfHeaders
    text_raw_size = align_up(len(code), FILE_ALIGNMENT)
    idata_raw_ptr = text_raw_ptr + text_raw_size
    idata_raw_size= align_up(len(idata_bytes), FILE_ALIGNMENT)

    # .text
    headers += struct.pack("<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        len(code), TEXT_RVA, text_raw_size, text_raw_ptr,
        0,0,0,0,
        0x60000020   # code | execute | read
    )
    # .idata
    headers += struct.pack("<8sIIIIIIHHI",
        b".idata\x00\x00",
        len(idata_bytes), IDATA_RVA, idata_raw_size, idata_raw_ptr,
        0,0,0,0,
        0x40000040   # initialized data | read
    )

    # Pad headers to SizeOfHeaders
    if len(headers) > SizeOfHeaders:
        raise SystemExit("Headers too large!")
    headers += b"\x00" * (SizeOfHeaders - len(headers))

    # File assembly
    out = bytearray()
    out += headers
    out += code
    out += b"\x00" * (text_raw_size - len(code))
    out += idata_bytes
    out += b"\x00" * (idata_raw_size - len(idata_bytes))
    return bytes(out)

def main():
    source_path = sys.argv[1] if len(sys.argv) >= 2 else None
    if source_path:
        try:
            with open(source_path, "rb") as f:
                data = f.read()
            if not data:
                raise ValueError("Input file is empty.")
            print(f"[+] using {source_path} (all {len(data)} bytes)")
        except Exception as e:
            print(f"[-] failed to read {source_path}: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        data = os.urandom(8 * 1024)
        print(f"[+] using /dev/urandom ({len(data)} bytes)")

    # Build sections
    idata_bytes, idata_info = build_idata()
    code, patches = generate_chaotic_code_windows(data)
    pe = build_pe_exe(code, idata_bytes, idata_info, patches)

    out = "a.exe"
    with open(out, "wb") as f:
        f.write(pe)
    print(f"[+] wrote {out} size={len(pe)} bytes")
    print(f"[+] entry RVA 0x{TEXT_RVA:08x}, ImageBase 0x{IMAGE_BASE:016x}")
    print("[!] WARNING: Random code. Run in a VM / sandbox.")
    print("    Expect console spam, CPU usage, or hangs.")

if __name__ == "__main__":
    main()
