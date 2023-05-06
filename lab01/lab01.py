#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import time
from pwn import *

def solve_pow(r):
    # [Proof-of-Work Access Rate Control: Given a prefix P = '5134b1d7'.
    prefix = r.recvline().decode().split("'")[1]
   
    print(time.time(), "solving pow ...")
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h[:6] == '000000':
            solved = str(i).encode()
            print("solved =", solved)
            break;
    print(time.time(), "done.")

    r.sendlineafter(b'string S: ', base64.b64encode(solved))

if __name__ == '__main__':
    r = remote('up23.zoolab.org', 10363)
    
    # print("start solving pow\n\n\n\n")
    solve_pow(r)
    
    # print("start solving arithmetic challenge\n\n\n\n")
    r.recvuntil(b'Please complete the ')
    num = int(r.recvuntil(b' ').decode())
    r.recvuntil(b'shortest binary number encoded in base64\n\n')
    
    # 1678447267.058383 1: 98300639 * 17320295 = ? 
    # eval('2 + 2') = 4
    
    for i in range(1, num+1):
        r.recvuntil(b' ')
        num_i = f"{i}: "
        r.recvuntil(num_i.encode())
        expression = r.recvuntil(b'=').decode()[:-2]

        big_num = eval(expression)
        bytes_le = big_num.to_bytes((big_num.bit_length() + 7) // 8, byteorder="little")
        encoded = base64.b64encode(bytes_le)

        print(f"{num_i} {expression} = {encoded.decode()}")
        r.sendline(encoded)

    output = b''
    while True:
        try:
            num_i_val = r.recv()
            if not num_i_val:
                break
            output += num_i_val
        except EOFError:
            break

    print(output)    
    
    #r.interactive()
    r.close()
    
    # r.recvuntil
    # r.sendlineafterd

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
