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
        "MOV EAX, 0            ;" // set default value to return
        "MOV ECX, 0            ;" // i = 0
        "MOV ESI, 46340        ;" // biggest root of an int
        "_LOOP:"
            "INC ECX           ;" // i++
            "CMP ECX, ESI      ;"
            "JG _FINISH        ;" // if (i > 46340) return 0
            "MOV EDX, ECX      ;"
            "IMUL EDX, EDX     ;"
            "CMP EDX, EBX      ;"
            "JL _LOOP          ;" // if (i*i < EBX)  goto _LOOP
            "JNE _FINISH       ;" // if (i*i > EBX)  return 0
            "MOV EAX, ECX      ;" // if (i*i == EBX) return i
        "_FINISH:"
    );

    asm ("MOV   %0, EAX"
        : "=r"(output));

    printf("%d\n", output);

    return 0;
}
