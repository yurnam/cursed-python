#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <psapi.h>
#include <shlwapi.h>
#include <tchar.h>

#define MAX_CHILDS 100
#define MAX_DEPTH 3
#define MAX_ARGS 255
#define MAX_BUF_SIZE 1048576  // 1MB max buffer

typedef struct {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} EXPORT_DIRECTORY;

void get_random_dll_and_func(TCHAR* dll_path, char*** func_names, int* num_funcs) {
    TCHAR root[] = _T("C:\\Windows");
    TCHAR current[MAX_PATH];
    _tcscpy(current, root);
    int depth = 0;
    *num_funcs = 0;
    *func_names = NULL;

    while (depth < MAX_DEPTH) {
        WIN32_FIND_DATA findFileData;
        TCHAR search_path[MAX_PATH];
        _stprintf(search_path, _T("%s\\*"), current);
        HANDLE hFind = FindFirstFile(search_path, &findFileData);

        if (hFind == INVALID_HANDLE_VALUE) break;

        int entry_count = 0;
        TCHAR entries[1024][MAX_PATH];
        do {
            if (_tcscmp(findFileData.cFileName, _T(".")) == 0 || _tcscmp(findFileData.cFileName, _T("..")) == 0) continue;
            _stprintf(entries[entry_count], _T("%s\\%s"), current, findFileData.cFileName);
            entry_count++;
        } while (FindNextFile(hFind, &findFileData) != 0);
        FindClose(hFind);

        if (entry_count == 0) break;

        int rand_idx = rand() % entry_count;
        _tcscpy(current, entries[rand_idx]);

        if ((GetFileAttributes(current) & FILE_ATTRIBUTE_DIRECTORY) == 0 && StrStrI(current, _T(".dll"))) {
            HANDLE hFile = CreateFile(current, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) continue;

            DWORD fileSize = GetFileSize(hFile, NULL);
            BYTE* fileData = (BYTE*)malloc(fileSize);
            if (!fileData) { CloseHandle(hFile); continue; }
            DWORD bytesRead;
            ReadFile(hFile, fileData, fileSize, &bytesRead, NULL);
            CloseHandle(hFile);

            if (bytesRead < sizeof(IMAGE_DOS_HEADER)) { free(fileData); continue; }
            IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { free(fileData); continue; }

            IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(fileData + dosHeader->e_lfanew);
            if (ntHeader->Signature != IMAGE_NT_SIGNATURE || ntHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) { free(fileData); continue; }

            DWORD exportRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (exportRVA == 0) { free(fileData); continue; }

            EXPORT_DIRECTORY* exportDir = (EXPORT_DIRECTORY*)(fileData + exportRVA);
            DWORD* nameRVAs = (DWORD*)(fileData + exportDir->AddressOfNames);
            WORD* ordinalRVAs = (WORD*)(fileData + exportDir->AddressOfNameOrdinals);
            DWORD* funcRVAs = (DWORD*)(fileData + exportDir->AddressOfFunctions);

            *num_funcs = exportDir->NumberOfNames;
            *func_names = (char**)malloc(*num_funcs * sizeof(char*));
            if (!*func_names) { free(fileData); continue; }
            for (int i = 0; i < *num_funcs; i++) {
                char* name = (char*)(fileData + nameRVAs[i]);
                (*func_names)[i] = _strdup(name);
                if (!(*func_names)[i]) {
                    for (int j = 0; j < i; j++) free((*func_names)[j]);
                    free(*func_names);
                    free(fileData);
                    *func_names = NULL;
                    *num_funcs = 0;
                    return;
                }
            }

            free(fileData);
            _tcscpy(dll_path, current);
            return;
        }

        depth++;
    }
}

void get_random_file_bytes(BYTE* buffer, size_t sz) {
    if (sz == 0) { memset(buffer, 0, sz); return; }

    TCHAR root[] = _T("C:\\");
    TCHAR current[MAX_PATH];
    _tcscpy(current, root);
    int depth = 0;
    int max_depth = 10;

    while (depth < max_depth) {
        WIN32_FIND_DATA findFileData;
        TCHAR search_path[MAX_PATH];
        _stprintf(search_path, _T("%s\\*"), current);
        HANDLE hFind = FindFirstFile(search_path, &findFileData);

        if (hFind == INVALID_HANDLE_VALUE) break;

        int entry_count = 0;
        TCHAR entries[1024][MAX_PATH];
        do {
            if (_tcscmp(findFileData.cFileName, _T(".")) == 0 || _tcscmp(findFileData.cFileName, _T("..")) == 0) continue;
            _stprintf(entries[entry_count], _T("%s\\%s"), current, findFileData.cFileName);
            entry_count++;
        } while (FindNextFile(hFind, &findFileData) != 0);
        FindClose(hFind);

        if (entry_count == 0) break;

        int rand_idx = rand() % entry_count;
        _tcscpy(current, entries[rand_idx]);

        if ((GetFileAttributes(current) & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            HANDLE hFile = CreateFile(current, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) continue;

            LARGE_INTEGER fileSize;
            GetFileSizeEx(hFile, &fileSize);
            if (fileSize.QuadPart == 0) { CloseHandle(hFile); continue; }

            LARGE_INTEGER start;
            start.QuadPart = rand() % fileSize.QuadPart;
            SetFilePointerEx(hFile, start, NULL, FILE_BEGIN);

            DWORD bytesToRead = (DWORD)min(sz, fileSize.QuadPart - start.QuadPart);
            ReadFile(hFile, buffer, bytesToRead, NULL, NULL);
            CloseHandle(hFile);
            return;
        }

        depth++;
    }
    memset(buffer, 0, sz);
}

void child_process() {
    srand((unsigned)GetCurrentProcessId() ^ (unsigned)time(NULL));

    TCHAR dll_path[MAX_PATH];
    char** func_names;
    int num_funcs;
    get_random_dll_and_func(dll_path, &func_names, &num_funcs);
    if (num_funcs == 0) return;

    char* func_name = func_names[rand() % num_funcs];

    HMODULE lib = LoadLibrary(dll_path);
    if (!lib) goto cleanup;

    FARPROC fn = GetProcAddress(lib, func_name);
    if (!fn) goto cleanup;

    BYTE** bufs = (BYTE**)malloc(64 * sizeof(BYTE*));
    if (!bufs) goto cleanup;
    for (int i = 0; i < 64; i++) {
        size_t sz = rand() % MAX_BUF_SIZE;
        bufs[i] = (BYTE*)malloc(sz);
        if (bufs[i]) get_random_file_bytes(bufs[i], sz);
    }

    while (1) {
        int nargs = rand() % MAX_ARGS;
        void* args[MAX_ARGS];
        for (int i = 0; i < nargs; i++) {
            int kind = rand() % 10;
            if (kind == 0) {
                UINT64 val = ((UINT64)rand() << 32) | rand();
                args[i] = (void*)val;
            } else if (kind == 1) {
                UINT64 val = rand() % 0x10000;
                args[i] = (void*)val;
            } else if (kind == 2) {
                args[i] = NULL;
            } else if (kind == 3 || kind == 4) {
                BYTE* b = bufs[rand() % 64];
                args[i] = (void*)b;
            } else if (kind == 5) {
                double* d = (double*)malloc(sizeof(double));
                if (d) *d = ((double)rand() / RAND_MAX) * 1e12 - 5e11;
                args[i] = d;
            } else if (kind == 6) {
                size_t sz = rand() % 4096;
                BYTE* s = (BYTE*)malloc(sz);
                if (s) get_random_file_bytes(s, sz);
                args[i] = s;
            } else if (kind == 7) {
                WCHAR* s = (WCHAR*)malloc(1024 * sizeof(WCHAR));
                if (s) {
                    for (int j = 0; j < 1023; j++) s[j] = (WCHAR)(rand() % 0xFFFF);
                    s[1023] = 0;
                }
                args[i] = s;
            } else if (kind == 8) {
                int val = rand();
                args[i] = (void*)(intptr_t)val;
            } else {
                UINT64 ptr = ((UINT64)rand() << 32) | rand();
                args[i] = (void*)ptr;
            }
        }

        // Call function with up to 4 args to avoid stack issues
        if (fn) {
            switch (nargs > 4 ? 4 : nargs) {
                case 0: ((void (*)())fn)(); break;
                case 1: ((void (*)(void*))fn)(args[0]); break;
                case 2: ((void (*)(void*, void*))fn)(args[0], args[1]); break;
                case 3: ((void (*)(void*, void*, void*))fn)(args[0], args[1], args[2]); break;
                case 4: ((void (*)(void*, void*, void*, void*))fn)(args[0], args[1], args[2], args[3]); break;
            }
        }

        // Minimal cleanup
        for (int i = 0; i < nargs; i++) {
            if ((rand() % 10) == 5 || (rand() % 10) == 6 || (rand() % 10) == 7) free(args[i]);
        }
    }

cleanup:
    if (lib) FreeLibrary(lib);
    for (int i = 0; i < num_funcs; i++) if (func_names[i]) free(func_names[i]);
    if (func_names) free(func_names);
    for (int i = 0; i < 64; i++) if (bufs && bufs[i]) free(bufs[i]);
    if (bufs) free(bufs);
}

int main(int argc, char* argv[]) {
    srand((unsigned)time(NULL));

    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        child_process();
        return 0;
    }

    HANDLE procs[MAX_CHILDS];
    int num_procs = 0;

    // Prefill
    for (int i = 0; i < MAX_CHILDS; i++) {
        STARTUPINFO si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        TCHAR cmd[] = _T("chaos.exe child");
        if (CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            procs[num_procs++] = pi.hProcess;
            CloseHandle(pi.hThread);
        }
    }

    while (1) {
        Sleep(50);
        int alive = 0;
        for (int i = 0; i < num_procs; i++) {
            if (WaitForSingleObject(procs[i], 0) == WAIT_TIMEOUT) {
                if (rand() % 100 < 5) {  // 5% chance to timeout
                    TerminateProcess(procs[i], 0);
                    CloseHandle(procs[i]);
                } else {
                    procs[alive++] = procs[i];
                }
            } else {
                CloseHandle(procs[i]);
            }
        }

        // Respawn to maintain MAX_CHILDS
        while (alive < MAX_CHILDS) {
            STARTUPINFO si = { sizeof(si) };
            PROCESS_INFORMATION pi;
            TCHAR cmd[] = _T("chaos.exe child");
            if (CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                procs[alive++] = pi.hProcess;
                CloseHandle(pi.hThread);
            } else {
                break;
            }
        }
        num_procs = alive;
    }

    return 0;
}