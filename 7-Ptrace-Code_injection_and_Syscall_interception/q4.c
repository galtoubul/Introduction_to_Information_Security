#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>

int pid = 0x12345678;

int main(int argc, char **argv) {
    // Make the malware stop waiting for our output by forking a child process:
    if (fork() != 0) {
        // Kill the parent process so we stop waiting from the malware
        return 0;
    } else {
        // Close the output stream so we stop waiting from the malware
        fclose(stdout);
    }

    // Attach to the process
    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1){
        perror("attach");
        return -1;
    }

    long orig_eax;
    int status;
    wait(&status); // Wait for the process to stop
    if(WIFEXITED(status)) { return 0; } // Abort if the process exits

    while(1){
        // Wait for a syscall
        if(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1){
            perror("syscall");
            return -1;
        }
        wait(&status); // Wait for the process to stop
        if(WIFEXITED(status)) { return 0; } // Abort if the process exits

        // Get eax
        if((orig_eax = ptrace(PTRACE_PEEKUSER, pid, 4 * ORIG_EAX, NULL)) == -1){
            perror("PTRACE_PEEKUSER");
            return -1;
        }

        // Catch read syscalls and modify their size to 0
        if(orig_eax == 0x03){
            if(ptrace(PTRACE_POKEUSER, pid, 4 * EDX, NULL) == -1){
                perror("PTRACE_POKEUSER");
                return -1;
            }
        }

        // Wait for a syscall
        if(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1){
            perror("syscall");
            return -1;
        }
        wait(&status); // Wait for the process to stop
        if(WIFEXITED(status)) { return 0; } // Abort if the process exits

        // Get eax
        if((orig_eax = ptrace(PTRACE_PEEKUSER, pid, 4 * ORIG_EAX, NULL)) == -1){
            perror("PTRACE_PEEKUSER");
            return -1;
        }

        // Catch read syscalls and modify their size to 0
        if(orig_eax == 0x03){
            if(ptrace(PTRACE_POKEUSER, pid, 4 * EDX, NULL) == -1){
                perror("PTRACE_POKEUSER");
                return -1;
            }
        }
    }
    return 0;
}
