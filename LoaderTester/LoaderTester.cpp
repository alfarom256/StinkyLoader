#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <string>
#define _LOADER_DEBUG
#include "../StinkyLoader/loader.h"

const char* help = R"(
wrong args:
   dummyloader.exe load/rload/xload dllname.dll 
)";

const char* init_func = "init";

typedef void (WINAPI* pTest)();
typedef uintptr_t(WINAPI* pInit)(uintptr_t);
typedef NTSTATUS(WINAPI* pNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);

BOOL do_load_normal(char* dll);
BOOL do_rload(char* dll);
BOOL do_xload(char* dll);

int main(int argc, char* argv[], char** envp) {

    if (argc != 3) {
        puts(help);
        return 0;
    }

    BOOL do_load = strncmp(argv[1], "load", strlen("load")) == 0;
    BOOL do_reflective_load = strncmp(argv[1], "rload", strlen("rload")) == 0;
    BOOL do_execute_reflective_load = strncmp(argv[1], "xload", strlen("xload")) == 0;

    if (!(do_load || do_reflective_load || do_execute_reflective_load)) {
        puts(help);
        return 0;
    }

    BOOL res = FALSE;

    char* data_file = argv[2];

    if (do_load) {
        res = do_load_normal(data_file);
    }
    else if (do_reflective_load) {
        res = do_rload(data_file);
    }
    else if (do_execute_reflective_load) {
        res = do_xload(data_file);
    }

    printf("Loading dll %s %s", data_file, res ? "succeeded" : "failed");
}

int filter(unsigned int code, struct _EXCEPTION_POINTERS* ep)
{
    puts("in filter.");
    if (code == EXCEPTION_ACCESS_VIOLATION)
    {
        puts("caught AV as expected.");
        return EXCEPTION_EXECUTE_HANDLER;
    }
    else
    {
        puts("didn't catch AV, unexpected.");
        return EXCEPTION_CONTINUE_SEARCH;
    };
}

BOOL do_load_normal(char* dll) {
    HMODULE hMod = LoadLibraryA(dll);
    if (!hMod) {
        return FALSE;
    }

    pTest stubInit = (pTest)GetProcAddress(hMod, init_func);
    if (!stubInit) {
        FreeLibrary(hMod);
        return FALSE;
    }

    stubInit();
    return TRUE;
}

BOOL do_rload(char* dll) {
    size_t size;
    LPVOID lpBuf = NULL;

    std::ifstream file(dll, std::ios::in | std::ios::binary | std::ios::ate);
    if (file.is_open())
    {
        size = file.tellg();

        lpBuf = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
        if (!lpBuf) {
            exit(1);
        }
        //printf("%x\n", GetLastError());
        file.seekg(0, std::ios::beg);
        file.read((char*)lpBuf, size);
        file.close();
    }
    else {
        std::cout << "Error opening file" << std::endl;
        return 0;
    }
    std::cout << "Loaded file : " << dll << std::endl;

    DWORD old = 0;
    VirtualProtect(lpBuf, size, PAGE_READWRITE, &old);
    uintptr_t lpNewBase = load((uintptr_t)lpBuf);

    if ((lpNewBase & 0xFF00000000000000) > 0) {
        printf("Failed with status %p\n", lpNewBase);
        return FALSE;
    }
    printf("Status %p\n", lpNewBase);
    return lpNewBase != 0;
}

BOOL do_xload(char* dll)
{
    size_t size;
    LPVOID lpBuf = NULL;

    std::ifstream file(dll, std::ios::in | std::ios::binary | std::ios::ate);
    if (file.is_open())
    {
        size = file.tellg();

        lpBuf = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
        if (!lpBuf) {
            exit(1);
        }
        //printf("%x\n", GetLastError());
        file.seekg(0, std::ios::beg);
        file.read((char*)lpBuf, size);
        file.close();
    }
    else {
        std::cout << "Error opening file" << std::endl;
        return 0;
    }
    std::cout << "Loaded file : " << dll << std::endl;

    DWORD old = 0;
    VirtualProtect(lpBuf, size, PAGE_EXECUTE_READWRITE, &old);

    pInit reflective_routine = (pInit)lpBuf;
    uintptr_t lpNewBase = reflective_routine((uintptr_t)lpBuf);

    return lpNewBase != NULL;
}

