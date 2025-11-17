#!/usr/bin/env python3

import os
import sys
import subprocess
from pwn import *

ROOT = os.path.abspath(os.path.dirname(__file__))
bin_path = os.path.join(ROOT, "../docker/target")

# Detect binary architecture using readelf for reliability
def detect_arch(binary_path):
    try:
        result = subprocess.run(['readelf', '-h', binary_path],
                              capture_output=True, text=True, check=True)
        if 'ELF32' in result.stdout:
            return 32
        elif 'ELF64' in result.stdout:
            return 64
    except:
        # Fallback to pwntools detection
        elf = ELF(binary_path, checksec=False)
        return elf.bits
    return 64  # Default to 64-bit if detection fails

arch_bits = detect_arch(bin_path)
if arch_bits == 32:
    context.arch = "i386"
else:
    context.arch = "x86_64"
context.log_level = 'error'

def test_basic_functionality():
    """Test basic operations without exploitation"""
    if "REMOTE" in os.environ:
        if not "PORT" in os.environ:
            print("[!] Please specify the port number")
            return False
        p = remote("localhost", int(os.environ["PORT"]))
    else:
        p = process(bin_path)

    try:
        # Wait for banner (═ is UTF-8 encoded as \xe2\x95\x90)
        p.recvuntil(b'\xe2\x95\x90')

        p.sendlineafter(b'> ', b'1')
        p.sendlineafter(b'(0-9): ', b'0')
        if b'Zone 0' not in p.recvuntil(b'> '):
            return False

        p.sendlineafter(b'> ', b'1')
        p.sendlineafter(b'(0-9): ', b'5')
        if b'Zone 5' not in p.recvuntil(b'> '):
            return False

        p.sendlineafter(b'> ', b'2')
        p.sendlineafter(b'(0-9): ', b'0')
        p.sendlineafter(b'max 128 bytes): ', b'Test data')
        if b'inscribed' not in p.recvuntil(b'> '):
            return False

        p.sendlineafter(b'> ', b'3')
        p.sendlineafter(b'(0-9): ', b'0')
        output = p.recvuntil(b'> ')
        if b'Test data' not in output or b'Address:' not in output:
            return False

        p.sendlineafter(b'> ', b'1')
        p.sendlineafter(b'(0-9): ', b'9')
        if b'Zone 9' not in p.recvuntil(b'> '):
            return False

        p.sendlineafter(b'> ', b'6')
        if b'Executing Timeline' in p.recvall(timeout=2):
            p.close()
            return True

    except Exception as e:
        print(f"Error: {e}")
        p.close()
        return False

    p.close()
    return False

if __name__ == '__main__':
    if test_basic_functionality():
        print("OK!")
        exit(0)
    else:
        print("FAILED!")
        exit(1)
