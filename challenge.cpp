#include <windows.h>
#include <cstdint>
#include <string>
#include <iostream>
#include <vector>
#include <cstring>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <iphlpapi.h>
#ifdef _M_X64
#include <intrin.h>
#endif

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#define FORCEINLINE __forceinline
#else
#define NOINLINE __attribute__((noinline))
#define FORCEINLINE __attribute__((always_inline))
#endif


typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
typedef NTSTATUS (WINAPI *pNtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS (WINAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (WINAPI *pNtClose)(HANDLE);
typedef NTSTATUS (WINAPI *pNtQueryObject)(HANDLE, DWORD, PVOID, ULONG, PULONG);

static std::string d1_unpack(const uint8_t* data, size_t len, uint8_t k) {
    std::string out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = static_cast<uint8_t>(data[i] ^ (k + static_cast<uint8_t>(i * 13u)));
        out.push_back(static_cast<char>(b));
    }
    return out;
}

static uint32_t x7_k9_mix(uint32_t a, uint32_t b) {
    volatile uint32_t va = a;
    volatile uint32_t vb = b;
    va ^= (vb + 0x9e3779b9u + (va << 6) + (va >> 2));
    va = (va << 13) | (va >> 19);
    va ^= (va >> 17);
    va *= 0x85ebca6bu;
    va ^= (va >> 13);
    va *= 0xc2b2ae35u;
    va ^= (va >> 16);
    return va;
}

FORCEINLINE static uint64_t z3_rdtsc() {
#ifdef _M_X64
    return __rdtsc();
#else
    uint32_t lo, hi;
    __asm {
        rdtsc
        mov lo, eax
        mov hi, edx
    }
    return ((uint64_t)hi << 32) | lo;
#endif
}

FORCEINLINE static PEB* q4_get_peb() {
#ifdef _M_X64
    return (PEB*)__readgsqword(0x60);
#else
    return (PEB*)__readfsdword(0x30);
#endif
}

NOINLINE static bool w8_dbg_chk1() {
    if (IsDebuggerPresent()) return true;
    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) return true;
    return false;
}

NOINLINE static bool w8_dbg_chk2() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) return false;
    DWORD dbgFlag = 0;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 7, &dbgFlag, sizeof(dbgFlag), NULL);
    if (status == 0 && dbgFlag != 0) return true;
    return false;
}

NOINLINE static bool w8_dbg_chk3() {
    uint64_t t1 = z3_rdtsc();
    Sleep(10);
    uint64_t t2 = z3_rdtsc();
    uint64_t diff = t2 - t1;
    if (diff > 200000000ULL) return true;
    return false;
}

NOINLINE static bool w8_dbg_chk4() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    int count = 0;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, "ollydbg.exe") == 0 ||
                _stricmp(pe32.szExeFile, "x64dbg.exe") == 0 ||
                _stricmp(pe32.szExeFile, "ida.exe") == 0 ||
                _stricmp(pe32.szExeFile, "ida64.exe") == 0 ||
                _stricmp(pe32.szExeFile, "windbg.exe") == 0 ||
                _stricmp(pe32.szExeFile, "devenv.exe") == 0 ||
                _stricmp(pe32.szExeFile, "wireshark.exe") == 0 ||
                _stricmp(pe32.szExeFile, "procmon.exe") == 0 ||
                _stricmp(pe32.szExeFile, "procmon64.exe") == 0 ||
                _stricmp(pe32.szExeFile, "scylla.exe") == 0 ||
                _stricmp(pe32.szExeFile, "scylla_hide.exe") == 0 ||
                _stricmp(pe32.szExeFile, "x64dbg.exe") == 0 ||
                _stricmp(pe32.szExeFile, "x32dbg.exe") == 0 ||
                _stricmp(pe32.szExeFile, "cheatengine-x86_64.exe") == 0 ||
                _stricmp(pe32.szExeFile, "cheatengine-i386.exe") == 0) {
                count++;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return count > 0;
}

NOINLINE static bool w8_dbg_chk5() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    pNtSetInformationThread NtSetInformationThread = (pNtSetInformationThread)GetProcAddress(ntdll, "NtSetInformationThread");
    if (NtSetInformationThread) {
        NtSetInformationThread(GetCurrentThread(), 0x11, NULL, 0);
    }
    return false;
}

NOINLINE static bool w8_dbg_chk6() {
    PEB* peb = q4_get_peb();
    if (!peb) return false;
    if (peb->BeingDebugged) return true;
    volatile BYTE* pebBytes = (volatile BYTE*)peb;
#ifdef _M_X64
    ULONG* ntGlobalFlag = (ULONG*)(pebBytes + 0xBC);
#else
    ULONG* ntGlobalFlag = (ULONG*)(pebBytes + 0x68);
#endif
    if (*ntGlobalFlag & 0x70) return true;
    return false;
}

NOINLINE static bool w8_dbg_chk7() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) return false;
    HANDLE hDebugObject = NULL;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 30, &hDebugObject, sizeof(hDebugObject), NULL);
    if (status == 0 && hDebugObject != NULL) {
        pNtClose NtClose = (pNtClose)GetProcAddress(ntdll, "NtClose");
        if (NtClose) NtClose(hDebugObject);
        return true;
    }
    return false;
}

NOINLINE static bool w8_dbg_chk8() {
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
#ifdef _M_X64
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) return true;
#else
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) return true;
#endif
    }
    return false;
}

NOINLINE static bool w8_dbg_chk9() {
    __try {
        RaiseException(0x40010006, 0, 0, NULL);
        return false;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode() != 0x40010006;
    }
}

NOINLINE static bool w8_dbg_chk10() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    FARPROC addr1 = GetProcAddress(ntdll, "NtQueryInformationProcess");
    FARPROC addr2 = GetProcAddress(ntdll, "NtSetInformationThread");
    if (!addr1 || !addr2) return false;
    uint8_t* p1 = (uint8_t*)addr1;
    uint8_t* p2 = (uint8_t*)addr2;
    if (p1[0] == 0xE9 || p1[0] == 0xEB || p2[0] == 0xE9 || p2[0] == 0xEB) return true;
    return false;
}

NOINLINE static bool v4_vm_chk1() {
    SYSTEM_INFO si;
    ZeroMemory(&si, sizeof(si));
    GetSystemInfo(&si);
    MEMORYSTATUSEX ms;
    ZeroMemory(&ms, sizeof(ms));
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    int score = 0;
    if (ms.ullTotalPhys <= (2ull * 1024ull * 1024ull * 1024ull)) score++;
    if (si.dwNumberOfProcessors <= 2) score++;
    char nameBuf[64] = {0};
    DWORD len = GetEnvironmentVariableA("COMPUTERNAME", nameBuf, sizeof(nameBuf));
    if (len > 0 && len < sizeof(nameBuf)) {
        if (std::strstr(nameBuf, "DESKTOP-") == nullptr &&
            std::strstr(nameBuf, "LAPTOP-") == nullptr &&
            std::strstr(nameBuf, "USER-") == nullptr) {
            score++;
        }
    }
    return score >= 3;
}

NOINLINE static bool v4_vm_chk2() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return false;
    DWORD size = 0;
    NtQuerySystemInformation(0x53, NULL, 0, &size);
    if (size > 0) {
        std::vector<uint8_t> buf(size);
        if (NtQuerySystemInformation(0x53, buf.data(), size, NULL) == 0) {
            if (size > 0x20) {
                uint32_t* p = (uint32_t*)buf.data();
                if (p[0] == 0x564D5868 || p[0] == 0x4D566D68) return true;
            }
        }
    }
    return false;
}

NOINLINE static bool v4_vm_chk3() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buf[256] = {0};
        DWORD size = sizeof(buf);
        if (RegQueryValueExA(hKey, "0", NULL, NULL, (LPBYTE)buf, &size) == ERROR_SUCCESS) {
            if (strstr(buf, "VMware") || strstr(buf, "VBOX") || strstr(buf, "QEMU") || strstr(buf, "Virtual")) {
                RegCloseKey(hKey);
                return true;
            }
        }
        RegCloseKey(hKey);
    }
    return false;
}

NOINLINE static bool v4_vm_chk4() {
    HMODULE hMod = LoadLibraryA("SbieDll.dll");
    if (hMod) {
        FreeLibrary(hMod);
        return true;
    }
    hMod = LoadLibraryA("cmdvrt32.dll");
    if (hMod) {
        FreeLibrary(hMod);
        return true;
    }
    hMod = LoadLibraryA("cmdvrt64.dll");
    if (hMod) {
        FreeLibrary(hMod);
        return true;
    }
    return false;
}

NOINLINE static bool v4_vm_chk5() {
#ifdef _M_X64
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] & 0x80000000) == 0) return false;
    __cpuid(cpuInfo, 0x40000000);
    if (cpuInfo[0] < 0x40000000) return false;
    if (cpuInfo[0] == 0x40000000 && cpuInfo[1] == 0 && cpuInfo[2] == 0 && cpuInfo[3] == 0) return false;
    char hypervisor[13] = {0};
    memcpy(hypervisor, &cpuInfo[1], 4);
    memcpy(hypervisor + 4, &cpuInfo[2], 4);
    memcpy(hypervisor + 8, &cpuInfo[3], 4);
    if (memcmp(hypervisor, "VMwareVMware", 12) == 0) return true;
    if (memcmp(hypervisor, "VBoxVBoxVBox", 12) == 0) return true;
    if (memcmp(hypervisor, "KVMKVMKVM", 9) == 0) return true;
#else
    int cpuInfo[4] = {0};
    __asm {
        mov eax, 1
        cpuid
        mov cpuInfo[0], eax
        mov cpuInfo[1], ebx
        mov cpuInfo[2], ecx
        mov cpuInfo[3], edx
    }
    if ((cpuInfo[2] & 0x80000000) == 0) return false;
    __asm {
        mov eax, 0x40000000
        cpuid
        mov cpuInfo[0], eax
        mov cpuInfo[1], ebx
        mov cpuInfo[2], ecx
        mov cpuInfo[3], edx
    }
    if (cpuInfo[0] < 0x40000000) return false;
    if (cpuInfo[0] == 0x40000000 && cpuInfo[1] == 0 && cpuInfo[2] == 0 && cpuInfo[3] == 0) return false;
    char hypervisor[13] = {0};
    memcpy(hypervisor, &cpuInfo[1], 4);
    memcpy(hypervisor + 4, &cpuInfo[2], 4);
    memcpy(hypervisor + 8, &cpuInfo[3], 4);
    if (memcmp(hypervisor, "VMwareVMware", 12) == 0) return true;
    if (memcmp(hypervisor, "VBoxVBoxVBox", 12) == 0) return true;
    if (memcmp(hypervisor, "KVMKVMKVM", 9) == 0) return true;
#endif
    return false;
}

NOINLINE static bool v4_vm_chk6() {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD dwBufLen = sizeof(adapterInfo);
    DWORD dwStatus = GetAdaptersInfo(adapterInfo, &dwBufLen);
    if (dwStatus == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapterInfo = adapterInfo;
        do {
            if (pAdapterInfo->AddressLength == 6) {
                uint8_t* mac = pAdapterInfo->Address;
                if ((mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) ||
                    (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) ||
                    (mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27) ||
                    (mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69)) {
                    return true;
                }
            }
            pAdapterInfo = pAdapterInfo->Next;
        } while (pAdapterInfo);
    }
    return false;
}

NOINLINE static bool v4_vm_chk7() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buf[256] = {0};
        DWORD size = sizeof(buf);
        if (RegQueryValueExA(hKey, "SystemBiosVersion", NULL, NULL, (LPBYTE)buf, &size) == ERROR_SUCCESS) {
            if (strstr(buf, "VMware") || strstr(buf, "VirtualBox") || strstr(buf, "VBOX") || 
                strstr(buf, "QEMU") || strstr(buf, "Xen")) {
                RegCloseKey(hKey);
                return true;
            }
        }
        RegCloseKey(hKey);
    }
    return false;
}

NOINLINE static std::string k5_hidden_name() {
    static const uint8_t kDat[] = {
        0x6D, 0x69, 0x6E, 0x74, 0x65, 0x64, 0x73, 0x65, 0x65
    };
    static const uint8_t kFake1[] = {
        0x66, 0x61, 0x6B, 0x65, 0x5F, 0x66, 0x6C, 0x61, 0x67, 0x5F, 0x31, 0x32, 0x33
    };
    static const uint8_t kFake2[] = {
        0x42, 0x45, 0x54, 0x54, 0x45, 0x52, 0x4D, 0x49, 0x4E, 0x54, 0x7B, 0x77, 0x72, 0x6F, 0x6E, 0x67, 0x7D
    };
    static const uint8_t kFake3[] = {
        0x68, 0x61, 0x63, 0x6B, 0x65, 0x72, 0x5F, 0x6D, 0x61, 0x6E
    };
    volatile uint8_t* pFake1 = const_cast<uint8_t*>(kFake1);
    volatile uint8_t* pFake2 = const_cast<uint8_t*>(kFake2);
    volatile uint8_t* pFake3 = const_cast<uint8_t*>(kFake3);
    (void)pFake1;
    (void)pFake2;
    (void)pFake3;
    std::string out;
    out.reserve(sizeof(kDat));
    volatile uint8_t v_mask = 0x00;
    for (size_t i = 0; i < sizeof(kDat); ++i) {
        char c = static_cast<char>(kDat[i] ^ v_mask);
        out.push_back(c);
    }
    return out;
}

NOINLINE static void k5_keep_name_alive(const std::string& userIn) {
    volatile size_t sz = userIn.size();
    volatile const char* fakeFlag1 = "BETTERMINT{not_the_flag}";
    volatile const char* fakeFlag2 = "BETTERMINT{try_harder}";
    volatile const char* fakeFlag3 = "BETTERMINT{you_are_close}";
    (void)fakeFlag1;
    (void)fakeFlag2;
    (void)fakeFlag3;
    if (sz == 0x1337u) {
        volatile auto dummy = k5_hidden_name();
        (void)dummy;
    }
    if (sz == 0xDEADu) {
        volatile auto dummy2 = k5_hidden_name();
        (void)dummy2;
    }
    if (sz == 0xCAFEu) {
        volatile const char* redHerring = "FLAG: BETTERMINT{red_herring_here}";
        (void)redHerring;
    }
}

NOINLINE static uint32_t m8_hash_func(const std::string& in, bool skew) {
    uint32_t seed = 0xC0FFEE11u;
    uint32_t stateA = 0x1234ABCDu;
    uint32_t stateB = 0xFEDC4321u;
    for (size_t i = 0; i < in.size(); ++i) {
        uint8_t c = static_cast<uint8_t>(in[i]);
        uint32_t mixed = c;
        mixed ^= static_cast<uint32_t>(i * 0x45u);
        mixed += (stateA ^ (stateB >> 3));
        stateA = x7_k9_mix(stateA, mixed);
        stateB = x7_k9_mix(stateB, stateA ^ mixed);
        uint32_t r = (stateA << (mixed & 7)) | (stateA >> (32 - (mixed & 7)));
        seed ^= r;
        seed = x7_k9_mix(seed, 0x9E3779B9u ^ mixed);
    }
    seed ^= (stateA + 0xDEAD1234u);
    seed ^= (stateB + 0x00F00DBAu);
    if (skew) {
        seed ^= 0xDEADBEEFu;
        seed = (seed << 3) | (seed >> 29);
    }
    return seed;
}

NOINLINE static bool p3_verify_input(const std::string& in, bool skewEnv) {
    return false;
}

NOINLINE static bool p3_verify_input_patched(const std::string& in, bool skewEnv) {
    std::string target = k5_hidden_name();
    return (in == target);
}


static const uint8_t STR_TROLL1[] = {
    0x77,0x68,0x79,0x20,0x61,0x72,0x65,0x20,0x79,0x6F,0x75,0x20,0x74,0x72,0x79,0x69,0x6E,0x67,0x20,0x74,0x6F,0x20,0x6C,0x6F,0x6F,0x6B,0x20,0x66,0x6F,0x72,0x20,0x73,0x74,0x72,0x69,0x6E,0x67,0x73,0x3F
};

static const uint8_t STR_TROLL2[] = {
    0x74,0x68,0x69,0x73,0x20,0x69,0x73,0x20,0x6E,0x6F,0x74,0x20,0x74,0x68,0x65,0x20,0x66,0x6C,0x61,0x67,0x20,0x79,0x6F,0x75,0x20,0x61,0x72,0x65,0x20,0x6C,0x6F,0x6F,0x6B,0x69,0x6E,0x67,0x20,0x66,0x6F,0x72
};

static const uint8_t STR_TROLL3[] = {
    0x6E,0x69,0x63,0x65,0x20,0x74,0x72,0x79,0x2C,0x20,0x62,0x75,0x74,0x20,0x6E,0x6F,0x70,0x65
};

static const uint8_t STR_TROLL4[] = {
    0x66,0x6C,0x61,0x67,0x3A,0x20,0x42,0x45,0x54,0x54,0x45,0x52,0x4D,0x49,0x4E,0x54,0x7B,0x66,0x61,0x6B,0x65,0x5F,0x66,0x6C,0x61,0x67,0x5F,0x68,0x65,0x72,0x65,0x7D
};

NOINLINE static void t9_troll_msgs() {
    volatile bool never = false;
    if (never) {
        std::string t1 = d1_unpack(STR_TROLL1, sizeof(STR_TROLL1), 0x00);
        std::string t2 = d1_unpack(STR_TROLL2, sizeof(STR_TROLL2), 0x00);
        std::string t3 = d1_unpack(STR_TROLL3, sizeof(STR_TROLL3), 0x00);
        std::string t4 = d1_unpack(STR_TROLL4, sizeof(STR_TROLL4), 0x00);
        std::cout << t1 << std::endl;
        std::cout << t2 << std::endl;
        std::cout << t3 << std::endl;
        std::cout << t4 << std::endl;
    }
}

int main() {
    t9_troll_msgs();
    
    bool dbg1 = w8_dbg_chk1();
    bool dbg2 = w8_dbg_chk2();
    bool dbg3 = w8_dbg_chk3();
    bool dbg4 = w8_dbg_chk4();
    w8_dbg_chk5();
    bool dbg6 = w8_dbg_chk6();
    bool dbg7 = w8_dbg_chk7();
    bool dbg8 = w8_dbg_chk8();
    bool dbg9 = w8_dbg_chk9();
    bool dbg10 = w8_dbg_chk10();
    
    bool vm1 = v4_vm_chk1();
    bool vm2 = v4_vm_chk2();
    bool vm3 = v4_vm_chk3();
    bool vm4 = v4_vm_chk4();
    bool vm5 = v4_vm_chk5();
    bool vm6 = v4_vm_chk6();
    bool vm7 = v4_vm_chk7();
    
    bool detected = dbg1 || dbg2 || dbg3 || dbg4 || dbg6 || dbg7 || dbg8 || dbg9 || dbg10 || 
                     vm1 || vm2 || vm3 || vm4 || vm5 || vm6 || vm7;
    
    if (detected) {
        ExitProcess(1);
    }
    
    std::string sWelcome = "Welcome to BetterMint Reverse Engineering Challenge!";
    std::string sPhase1  = "Phase 1: Find the hidden flag in this binary";
    std::string sPhase2  = "Phase 2: Patch the binary to accept the flag";
    std::string sPrompt  = "Enter key: ";
    std::string sOk      = "Access granted! You found the flag!";
    std::string sFail    = "Access denied";

    std::cout << sWelcome << "\n\n";
    std::cout << sPhase1 << "\n";
    std::cout << sPhase2 << "\n\n";

    std::cout << sPrompt;
    std::string userIn;
    std::getline(std::cin, userIn);

    k5_keep_name_alive(userIn);

    bool ok = p3_verify_input(userIn, detected);

    if (ok) {
        std::cout << sOk << "\n";
        std::cout << "FLAG: BETTERMINT{" << userIn << "}\n";
    } else {
        std::cout << sFail << "\n";
    }

    Sleep(300);
    return 0;
}
