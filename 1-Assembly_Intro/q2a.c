#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
    int input, output;

    if (argc != 2) {
        printf("USAGE: %s <number>\n", argv[0]);
        return -1;
    }

    input = atoi(argv[1]);

    asm ("MOV   EBX, %0"
        :
        : "r"(input));

    asm (
        "PUSH EBX;"
        "CALL _SQUAREBONACCI;"
        "ADD ESP, 4;"
        "JMP _FINISH;"
        
        "_SQUAREBONACCI:"

            // prologue
            "PUSH EBP;"
            "MOV EBP, ESP;"

            // recursion base cases
            "MOV EBX, [ESP + 8];"
            "CMP EBX, 0;"
            "JLE _EQUAL_ZERO;"
            "CMP EBX, 1;"
            "JE _EQUAL_ONE;"

            // EAX = _SQUAREBONACCI(EBX - 1)
            "DEC EBX;"
            "PUSH EBX;"
            "CALL _SQUAREBONACCI;"
            "POP EBX;"
            "PUSH EAX;" // store EAX

            // EDX = _SQUAREBONACCI(EBX - 2)
            "DEC EBX;"
            "PUSH EBX;"
            "CALL _SQUAREBONACCI;"
            "POP EBX;"
            "MOV EDX, EAX;"
            
            // EAX = EAX**2 + EDX**2
            "POP EAX;"
            "IMUL EAX, EAX;"
            "IMUL EDX, EDX;"
            "ADD EAX, EDX;"
            "JMP _EPILOGUE;"

        "_EQUAL_ZERO:"
            "MOV EAX, 0;"
            "JMP _EPILOGUE;"

        "_EQUAL_ONE:"
            "MOV EAX, 1;"

        "_EPILOGUE:"
            "MOV ESP, EBP;"
            "POP EBP;"
            "RET;"

        "_FINISH:"
    );

    asm ("MOV   %0, EAX"
        : "=r"(output));

    printf("%d\n", output);

    return 0;
}
