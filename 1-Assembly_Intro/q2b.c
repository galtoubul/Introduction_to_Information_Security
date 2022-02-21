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
        // check base cases
        "CMP EBX, 0;"
        "JLE _EQUAL_ZERO;"
        "CMP EBX, 1;"
        "JE _EQUAL_ONE;"

        // assitance registers
        "MOV ESI, 0;" // prevPrev
        "MOV EDI, 1;" // prev
        "MOV ECX, 1;"

        "_SQUAREBONACCI_LOOP:"
            // result = prevPrev*prevPrev + prev*prev
            "MOV EDX, ESI;"
            "IMUL EDX, EDX;"
            "MOV EAX, EDX;"
            "MOV EDX, EDI;"
            "IMUL EDX, EDX;"
            "ADD EAX, EDX;"

            "MOV ESI, EDI;" // prevPrev = prev
            "MOV EDI, EAX;" // prev = res

            // loop handling
            "INC ECX;"
            "CMP ECX, EBX;"
            "JNE _SQUAREBONACCI_LOOP;"
            "JMP _FINISH;"

        "_EQUAL_ZERO:"
            "MOV EAX, 0;"
            "JMP _FINISH;"

        "_EQUAL_ONE:"
            "MOV EAX, 1;"

        "_FINISH:"
    );

    asm ("MOV   %0, EAX"
        : "=r"(output));

    printf("%d\n", output);

    return 0;
}
