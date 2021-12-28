global _start

section .text

jmp _start

exit:
	xor rax, rax
	mov al, 60
	syscall
	ret

_start:
	xor rbx, rbx
	add rdi, 1
	mov bl, byte [rdi]
	cmp bl, 79
	jne short exit
	jmp _start
	ret 

