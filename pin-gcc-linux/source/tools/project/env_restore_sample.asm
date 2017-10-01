# Commands:
# as SOURCE.asm -o DEST.o
# objcopy -O binary DEST.o DEST.bin
# objdump -D -Mintel,x86-64 -b binary -m i386 DEST.bin

	lea    -128(%rsp), %rsp
	pushf	# push FLAGS register

	push %rdi
	push %rsi
	push %rdx
	push %rcx

	push   %rbp			# creating stack frame
	mov    %rsp,%rbp	# creating stack frame
	push   %rax
	push   %r8
	push   %r9
	push   %r10
	push   %r11

					# Using XED, set arguments to regs
lbl:	call lbl	# TODO: fix me to go to the C function
	
	pop    %r11
	pop    %r10
	pop    %r9
	pop    %r8
	pop    %rax
	leave		# clear stack frame
	
	pop %rcx
	pop %rdx
	pop %rsi
	pop %rdi

	popf	# pop FLAGS register
	lea    128(%rsp), %rsp

