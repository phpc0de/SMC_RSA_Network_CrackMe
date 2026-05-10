// CrackMe.cpp - 完整客户端（十种暗桩 + SMC + RSA + 网络验证）
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winhttp.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "psapi.lib")
__declspec(noinline) int VerifyRSA(const char* name, const char* serial);

// ========== 预期代码校验和（编译后替换） ==========
const DWORD EXPECTED_TEXT_CHECKSUM = 0x0064CF7C;

// ========== 暗桩检测函数（十个） ==========
bool CheckHardwareBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;
    }
    return false;
}

bool CheckSoftwareBreakpoint() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return false;
    FARPROC pIsDbg = GetProcAddress(hKernel32, "IsDebuggerPresent");
    if (!pIsDbg) return false;
    BYTE* ptr = (BYTE*)pIsDbg;
    // 检查函数前 4 个字节是否有 0xCC（INT3）
    for (int i = 0; i < 4; i++) {
        if (ptr[i] == 0xCC) return true;
    }
    return false;
}

bool CheckHypervisor() {
    int cpuInfo[4] = { 0 };
    __cpuidex(cpuInfo, 1, 0);
    return (cpuInfo[2] & (1 << 31)) != 0;
}

bool CheckSandboxModule() {
    const wchar_t* badDlls[] = { L"SbieDll.dll", NULL };  // 仅检测 Sandboxie
    for (int i = 0; badDlls[i]; i++) {
        if (GetModuleHandle(badDlls[i])) return true;
    }
    return false;
}

bool CheckParentProcess() {
    const wchar_t* badParents[] = {
        L"devenv.exe",     // Visual Studio
        L"msvsmon.exe",    // VS 远程调试器
        L"x64dbg.exe",
        L"x32dbg.exe",
        L"ollydbg.exe",
        L"windbg.exe",
        L"ida.exe",
        L"ida64.exe",
        L"processhacker.exe",
        L"procmon.exe",
        NULL
    };

    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                DWORD ppid = pe.th32ParentProcessID;
                CloseHandle(snap);
                HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
                if (hParent) {
                    wchar_t path[MAX_PATH];
                    DWORD len = MAX_PATH;
                    if (QueryFullProcessImageName(hParent, 0, path, &len)) {
                        wchar_t* name = wcsrchr(path, L'\\');
                        if (name) name++; else name = path;
                        for (int i = 0; badParents[i]; i++) {
                            if (_wcsicmp(name, badParents[i]) == 0) {
                                CloseHandle(hParent);
                                return true;
                            }
                        }
                    }
                    CloseHandle(hParent);
                }
                return false;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return false;
}

DWORD CalculateTextChecksum() {
    HMODULE hMod = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    DWORD textRVA = nt->OptionalHeader.BaseOfCode;
    DWORD textSize = nt->OptionalHeader.SizeOfCode;
    BYTE* textStart = (BYTE*)hMod + textRVA;
    DWORD sum = 0;
    for (DWORD i = 0; i < textSize; i++) sum += textStart[i];
    return sum;
}

DWORD CollectFlags() {
    DWORD flags = 0;
    BYTE* peb = (BYTE*)__readgsqword(0x60);

    if (peb && peb[2])                          flags |= 1 << 0;
    if (peb && (*(DWORD*)(peb + 0x68) & 0x70))  flags |= 1 << 1;

    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    if (remote)                                  flags |= 1 << 2;

    DWORD start = GetTickCount();
    Sleep(100);
    if (GetTickCount() - start > 150)            flags |= 1 << 3;

    if (CheckHardwareBreakpoints())              flags |= 1 << 4;
    if (CheckSoftwareBreakpoint())               flags |= 1 << 5;
 //   if (CheckHypervisor())                       flags |= 1 << 6;
    if (CheckSandboxModule())                    flags |= 1 << 7;
    if (CheckParentProcess())                    flags |= 1 << 8;
 //   if (CalculateTextChecksum() != EXPECTED_TEXT_CHECKSUM) flags |= 1 << 9;

    return flags;
}

// ========== SMC 解密与调用 ==========
#include "smc_data.h"

typedef int (*VerifyFunc)(const char* name, const char* serial);

VerifyFunc smc_unlock_verify() {
    void* execMem = VirtualAlloc(NULL, smc_code_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!execMem) return NULL;

    for (size_t i = 0; i < smc_code_len; i++) {
        ((unsigned char*)execMem)[i] = smc_code[i] ^ 0x5A;
    }
    FlushInstructionCache(GetCurrentProcess(), execMem, smc_code_len);
    return (VerifyFunc)execMem;
}

// ========== 网络验证 ==========
BOOL SendVerifyRequest(const char* name, const char* serial, DWORD flags) {
    BOOL bResults = FALSE;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    hSession = WinHttpOpen(L"User/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession)
        hConnect = WinHttpConnect(hSession, L"127.0.0.1", 8080, 0);
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/verify", NULL,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (hRequest) {
        char data[512];
        sprintf(data, "name=%s&serial=%s&flags=%u", name, serial, flags);
        DWORD dataLen = (DWORD)strlen(data);
        bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (LPVOID)data, dataLen, dataLen, 0) &&
            WinHttpReceiveResponse(hRequest, NULL);
    }
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return bResults == TRUE;
}

// ========== 主函数 ==========
int main() {
    setvbuf(stdout, NULL, _IONBF, 0);

    // 暗桩检测
    DWORD flags = CollectFlags();
    if (flags != 0) {
        printf("[!] Debug flags triggered: 0x%X\n", flags);
    }

    // 解密 SMC
    printf("[STEP] Unlocking SMC...\n");
    VerifyFunc Verify = smc_unlock_verify();
    if (!Verify) {
        printf("[ERROR] SMC unlock failed!\n");
        system("pause");
        return 1;
    }
    printf("[STEP] SMC unlocked at %p\n", Verify);

    // 输入
    char name[128], serial[1024];
    printf("Enter name: ");
    scanf("%127s", name);
    printf("Enter serial (hex): ");
    scanf("%1023s", serial);

    // 调用 SMC 保护的验证函数
    printf("[STEP] Calling SMC verify...\n");
    int result = Verify(name, serial);
    printf("[STEP] SMC verify returned: %d\n", result);

    if (result) {
        // 网络验证（可选）
        int netResult = SendVerifyRequest(name, serial, 0);
        printf("[STEP] Network returned: %d\n", netResult);
        if (netResult) {
            printf("Access granted!\n");
        }
        else {
            printf("Access denied! (network)\n");
        }
    }
    else {
        printf("Access denied!\n");
    }

    VirtualFree((void*)Verify, 0, MEM_RELEASE);
    system("pause");
    return 0;
}