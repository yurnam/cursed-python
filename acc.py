#!/usr/bin/env python3
# acc — the "chaos compiler"
# Usage: ./acc [file] -> uses all file bytes for chaotic x86-64 code
#        ./acc -> uses /dev/urandom
# Produces ./a.out: ELF64 x86-64 binary suitable as PID 1
import os, sys, struct
PAGE = 0x1000
BASE_VADDR = 0x400000
ELF_HDR = 64
PHDR = 56
def pad_to_multiple(b: bytes, mult: int, min_len: int) -> bytes:
    if len(b) < min_len:
        b += os.urandom(min_len - len(b))
    r = len(b) % mult
    if r:
        b += os.urandom(mult - r)
    return b
def s32(x): return struct.pack("<i", x)
def generate_chaotic_code(input_bytes: bytes) -> bytes:
    code = bytearray()
    loop_top = len(code)
    # Initialize registers
    for i in range(0, min(8, len(input_bytes))):
        val = input_bytes[i] if i < len(input_bytes) else 0
        reg = [b"\x48\xC7\xC0", b"\x48\xC7\xC3", b"\x48\xC7\xC1", b"\x48\xC7\xC2"][i % 4]
        code += reg + bytes([val, 0, 0, 0])
    # Allocate 4KB buffer and set rbx
    code += b"\x48\x81\xEC\x00\x10\x00\x00"  # sub rsp, 0x1000
    code += b"\x48\x89\xE3"  # mov rbx, rsp
    # Main loop
    for i in range(0, len(input_bytes), 4):
        chunk = input_bytes[i:i+4]
        op = chunk[0] % 6 if len(chunk) > 0 else 0
        val = int.from_bytes(chunk, "little") % 0x1000 if len(chunk) > 0 else 0
        # Reset rbx every 256 iterations to stay in buffer
        if i % 256 == 0:
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
            # write syscall to stdout
            code += b"\x48\xC7\xC0\x01\x00\x00\x00"  # mov rax, 1 (write)
            code += b"\x48\xC7\xC7\x01\x00\x00\x00"  # mov rdi, 1 (stdout)
            code += b"\x48\x89\xDE"  # mov rsi, rbx
            code += b"\x48\xC7\xC2\x08\x00\x00\x00"  # mov rdx, 8
            code += b"\x0F\x05"  # syscall
        elif op == 5:
            # Safe syscalls (0-9)
            syscall_num = chunk[0] % 10
            code += b"\x48\xC7\xC0" + bytes([syscall_num, 0, 0, 0])
            code += b"\x48\xC7\xC7\x00\x00\x00\x00"  # mov rdi, 0 (stdin)
            code += b"\x48\x89\xDE"  # mov rsi, rbx
            code += b"\x48\xC7\xC2\x08\x00\x00\x00"  # mov rdx, 8
            code += b"\x0F\x05"  # syscall
    # Loop back
    off_jmp = len(code)
    code += b"\xE9\x00\x00\x00\x00"
    code_vaddr = BASE_VADDR + PAGE
    rip_after = code_vaddr + off_jmp + 5
    rel = (code_vaddr + loop_top) - rip_after
    code[off_jmp + 1:off_jmp + 5] = s32(rel)
    return bytes(code)
def build_binary(arg_blob: bytes, code_off: int = PAGE) -> bytes:
    code = generate_chaotic_code(arg_blob)
    phoff = ELF_HDR
    e_entry = BASE_VADDR + code_off
    e_ident = b"\x7fELF" + bytes([2,1,1,0]) + b"\x00"*8
    ehdr = struct.pack("<16sHHIQQQIHHHHHH",
        e_ident, 2, 62, 1, e_entry, phoff, 0, 0,
        ELF_HDR, PHDR, 1, 0, 0, 0
    )
    phdr = struct.pack("<IIQQQQQQ",
        1, 5, 0, BASE_VADDR, BASE_VADDR, 0, 0, PAGE
    )
    prefix = bytearray(ehdr + phdr)
    if len(prefix) > code_off:
        raise SystemExit(f"code_off 0x{code_off:x} too small for headers ({len(prefix)} bytes).")
    prefix = prefix.ljust(code_off, b"\x00")
    blob = bytes(prefix) + code
    p_filesz = len(blob)
    p_memsz = p_filesz
    phdr_final = struct.pack("<IIQQQQQQ", 1, 5, 0, BASE_VADDR, BASE_VADDR, p_filesz, p_memsz, PAGE)
    blob = bytearray(blob)
    blob[ELF_HDR:ELF_HDR+PHDR] = phdr_final
    return bytes(blob)
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
        print(f"[+] using /dev/urandom ({len(data)} bytes)")
    elf = build_binary(data, code_off=PAGE)
    out = "a.out"
    with open(out, "wb") as f:
        f.write(elf)
    os.chmod(out, 0o755)
    print(f"[+] wrote {out} size={len(elf)} bytes")
    print(f"[+] entry @ 0x{BASE_VADDR + PAGE:016x}")
    print("[!] WARNING: Binary runs chaotic but valid code. Use in a VM!")
    print(" Expect console spam, CPU usage, or hangs.")
if __name__ == "__main__":
    main()
