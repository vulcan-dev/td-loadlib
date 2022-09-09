#include <stdio.h>
#include <stdlib.h>

#define _CRT_SECURE_NO_WARNINGS

#ifndef _WIN32
#error "Unsupported platform"
#else
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <TlHelp32.h>
#include "dirent.h"

// helper functions
void shutdown(const char* msg, int code) {
    printf("%s\n", msg);
    Sleep(3000);
    exit(code);
}

void shutdown_error(const char *msg) {
    DWORD err = GetLastError();
    LPVOID msg_buf;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &msg_buf, 0, NULL);

    const char* msg_fmt = "%s: %s (%d)";
    size_t msg_size = strlen(msg_fmt) + strlen(msg) + strlen(msg_buf) + 11;
    char* msg_final = malloc(msg_size);
    sprintf_s(msg_final, msg_size, msg_fmt, msg, msg_buf, err);
    shutdown(msg_final, 1);
}

DWORD get_pid_by_name(const char *name) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry) == TRUE) {
        do {
            if (strcmp(entry.szExeFile, name) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry) == TRUE);
    }

    CloseHandle(snapshot);
    return 0;
}

// steam functions
const char* get_steam_path() {
    char* steam_path = malloc(MAX_PATH);
    HKEY steam_key;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\Steam", 0, KEY_QUERY_VALUE, &steam_key) != ERROR_SUCCESS) {
        printf("Failed to open registry key\n");
        return NULL;
    }

    DWORD steam_path_size = MAX_PATH;
    if (RegQueryValueExA(steam_key, "InstallPath", NULL, NULL, (LPBYTE)steam_path, &steam_path_size) != ERROR_SUCCESS) {
        printf("Failed to query registry value\n");
        return NULL;
    }

    RegCloseKey(steam_key);
    return steam_path;
}

const char* get_game_path() {
    const char* steam_path = get_steam_path();
    if (steam_path == NULL) {
        return NULL;
    }

    char* game_path = malloc(MAX_PATH);

    // look for the game in the steam installation directory
    sprintf_s(game_path, MAX_PATH, "%s\\steamapps\\common\\Teardown", steam_path);
    DIR* dir = opendir(game_path);
    if (dir) {
        closedir(dir);
        return game_path;
    }

    // read the libraryfolders.vdf file to find the game
    sprintf_s(game_path, MAX_PATH, "%s\\steamapps\\libraryfolders.vdf", steam_path);
    FILE* file;
    fopen_s(&file, game_path, "r");
    if (file == NULL) {
        printf("Failed to open libraryfolders.vdf\n");
        return NULL;
    }

    char line[1024];
    while (fgets(line, sizeof(line), file) != NULL) {
        if (sscanf_s(line, "\"%*d\" \"%[^\"]\"", game_path, MAX_PATH) == 1) {
            sprintf_s(game_path, MAX_PATH, "%s\\steamapps\\common\\Teardown", game_path);
            dir = opendir(game_path);
            if (dir) {
                closedir(dir);
                return game_path;
            }
        }
    }

    printf("Failed to find game path\n");
    return NULL;
}

int main(void) {
    // check if the game is already running
    if (get_pid_by_name("teardown.exe") != 0) {
        shutdown("teardown is already running, please close the game and then run this.", 0);
    }

    // get the game path
    const char* game_path = get_game_path();
    if (game_path == NULL) {
        return 1;
    }

    printf("game path: %s\n", game_path);

    const char* game_exe = "teardown.exe";
    char* game_exe_path = malloc(strlen(game_path) + strlen(game_exe) + 2);
    sprintf_s(game_exe_path, strlen(game_path) + strlen(game_exe) + 2, "%s\\%s", game_path, game_exe);

    // check if we have the required dll, it should be in the same directory as the launcher
    char* current_path = malloc(MAX_PATH);
    GetModuleFileNameA(NULL, current_path, MAX_PATH);
    char* last_slash = strrchr(current_path, '\\');
    if (last_slash == NULL) {
        shutdown_error("failed to get current path");
    }
    *last_slash = '\0';

    char* dll_path = malloc(MAX_PATH);
    sprintf_s(dll_path, MAX_PATH, "%s\\teardown_hook.dll", current_path);
    FILE* dll_file;
    fopen_s(&dll_file, dll_path, "r");
    if (dll_file == NULL) {
        shutdown("failed to find teardown_hook.dll, please make sure it is in the same directory as the launcher.", 1);
    }

    printf("dll path: %s\n", dll_path);

    FILE* game_file;
    fopen_s(&game_file, game_exe_path, "r");
    if (game_file == NULL) {
        shutdown("failed to find teardown.exe", 1);
    }

    fseek(game_file, 0, SEEK_END);
    long game_size = ftell(game_file);
    rewind(game_file);

    void* game_data = malloc(game_size);
    if (game_data == NULL) {
        shutdown_error("failed to allocate memory for game data");
    }

    fread(game_data, 1, game_size, game_file);
    fclose(game_file);

    SetEnvironmentVariableA("SteamAppId", "1167630");

    // launch the game and inject the dll
    STARTUPINFOA startup_info;
    PROCESS_INFORMATION process_info;
    ZeroMemory(&startup_info, sizeof(startup_info));
    startup_info.cb = sizeof(startup_info);
    ZeroMemory(&process_info, sizeof(process_info));

    // launch game with the dll injected into it. resume the game as soon as the dll is injected
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    char* exe_path = malloc(MAX_PATH);
    sprintf_s(exe_path, MAX_PATH, "%s\\teardown.exe", game_path);

    if (CreateProcessA(NULL, exe_path, NULL, NULL, TRUE, CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED, NULL, game_path, &si, &pi) == 0) {
        shutdown_error("failed to create process");
    }

    printf("process created\n");

    // allocate memory for the dll
    LPVOID remote_dll = VirtualAllocEx(pi.hProcess, NULL, strlen(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (remote_dll == NULL) {
        shutdown_error("failed to allocate memory for dll path");
    }

    printf("remote dll: %p\n", remote_dll);

    // write the dll path to the game process
    if (WriteProcessMemory(pi.hProcess, remote_dll, dll_path, strlen(dll_path) + 1, NULL) == 0) {
        shutdown_error("failed to write dll path to game process");
    }

    // get address of LoadLibraryA
    LPVOID load_library = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (load_library == NULL) {
        shutdown_error("failed to get address of LoadLibraryA");
    }

    printf("load library: %p\n", load_library);

    // create a remote thread to load the dll
     HANDLE thread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)load_library, remote_dll, 0, NULL);
     if (thread == NULL) {
         shutdown_error("failed to create remote thread");
     }

    printf("remote thread created\n");
    
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);

    VirtualFreeEx(pi.hProcess, remote_dll, 0, MEM_RELEASE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}