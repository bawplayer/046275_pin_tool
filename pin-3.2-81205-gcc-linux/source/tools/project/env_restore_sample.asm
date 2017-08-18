	lea    -128(%rsp), %rsp
	pushf	# push FLAGS register

	push %rdi
	push %rsi

# function prototype should be:
# foo(unsigned long pc, unsigned long addr)
	call marker		# pushes the address of marker to the stack
marker:
	pop %rdi # C functions on x86_64 receive the 1st paremeter in rdi, 2nd parameter in rsi
	mov %rax, %rsi # value held by rax (pointer to address to be accessed)

	push   %rbp		# creating stack frame
	mov    %rsp,%rbp	# creating stack frame
	push   %rax
	push   %rdx
	push   %rcx
	push   %r8
	push   %r9
	push   %r10
	push   %r11

lbl:	call lbl	# TODO: fix me to go to the C function
	
	pop    %r11
	pop    %r10
	pop    %r9
	pop    %r8
	pop    %rcx
	pop    %rdx
	pop    %rax
	leave		# clear stack frame
	
	pop %rsi
	pop %rdi

	popf	# pop FLAGS register
	lea    128(%rsp), %rsp

