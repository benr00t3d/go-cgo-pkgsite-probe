	.section .rodata
	.balign 16
	.global embedded_client_start
	.global embedded_client_end
embedded_client_start:
	.incbin "canary-client"
embedded_client_end:

	.section .note.GNU-stack,"",@progbits
