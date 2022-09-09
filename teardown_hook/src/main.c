#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

DWORD WINAPI ThreadProc(LPVOID lpParameter);

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinst);
            CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
            break;
        case DLL_PROCESS_DETACH:
            FreeConsole();
            break;
        default:
            break;
    }

    return 1;
}

DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);

    return 0;
}