#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdint>
#include <filesystem>
#include <format>
#include <iostream>
#include <thread>

#include "MinHook.h"
#include "Sig.hpp"

typedef char **(*hwid_t)(char **);
hwid_t oHwid = nullptr;

char **hwid(char **ret) {
    oHwid(ret);
    const auto s = std::string("---------Hi-Korepi-Devs---------");
    memcpy(*ret, s.c_str(), s.size() + 1);

    return ret;
}

bool fakeResp = false;
bool fakeRespVerInfo = false;

typedef void (*options_t)(void *, size_t, void *);
options_t oOptions = nullptr;

void* userData;
typedef size_t(*callback_t)(char* ptr, size_t size, size_t nmemb, void* userdata);
callback_t Callback = nullptr;

void options(void *a1, size_t a2, void *a3) {
	if (a2 == 10002) {
        if (memcmp(a3, "https://md5c.", 13) == 0) {
            std::cout << "[Crack] Fake md5c response triggered" << std::endl;
            fakeResp = true;
        }
        if (memcmp(a3, "https://ghp.535888", 18) == 0) {
            std::cout << "[Crack] Fake version info response triggered" << std::endl;
            fakeRespVerInfo = true;
        }
    }

    if (a2 == 10001) {
        userData = a3;
    }

    if (a2 == 20011) {
    	Callback = (callback_t)a3;
	}
	oOptions(a1, a2, a3);
}

const std::string versionInfoResp = R"|({
    "msg": "success",
    "code": 200,
    "data": {
        "latest_version": "1.3.1.3",
        "update_required": true,
        "update_url": "https://github.com/Cotton-Buds/calculator/releases",
        "announcement": "4.6 os&cn",
        "updated_by": "Cracked",
        "updated_at": "1337",
        "update_diff": {
            "added_features": [
                "Cracked",
                "Cracked"
            ],
            "deleted_features": [
                "Cracked",
                "Cracked"
            ],
            "total_size": "1337"
        },
        "compatible_versions": [
            "none"
        ]
    },
    "sign2": "V4XAGPDh0GCOquiQyLUsTE90voX23qkYZbwc+Pa0qhMAWtKxYozxA/aE0U6BcXk502nZSrtHAXLh3ucIDFUuNX/T9uR+NpJmOirHbAJcH6z/xpzxywCVoGaFdchQ64A0RcxphpTI4bCeCr4mgXYXbIdGWd7+y6hpQ1qGcn9en0Oh9ULG11nL4iC0c4tK6N0zQLYSxmz8dOrhwg4CIkcRxx7Yht+1w/PEo0rR0GkKN3mONibiow2Bv8oSvev4vc0xvNZQ2gdPYzNxfg6ueCv4MXLDffzJ0nCrl8+xVwQs4mYLTYsovfBB/41kNbBoYGbzyTS+HesxTqsuDpU+1/oByg=="
}
)|";

const std::string resp = R"({
    "msg": "Hi there",
    "code": 200,
    "data": {
        "createBy": null,
        "createTime": "2024-05-25T14:06:09.662Z",
        "updateBy": "anonymousUser",
        "updateTime": "2024-05-25T14:06:09.662Z",
        "delFlag": 0,
        "remark": "Oops!",
        "id": 44262,
        "roleValue": 25,
        "cardKey": null,
        "expiryTime": "2038-01-19T03:14:07.000Z",
        "lastLoginTime": "2024-05-25T14:06:09.662Z",
        "hwid": "---------Hi-Korepi-Devs---------",
        "fileMd5": "mokPVuACUwR5Qw==",
        "resetTime": null,
        "resetNum": 4,
        "pauseTime": null,
        "status": 0
    },
    "signature": "a5879201e7fb4e3064390fccb0d8bbcf628c70bb237843101f314710ebfa0adc",
    "sign2": "coUVZrl9x43Dql30LoOOpp/U7+gVb7298CeYu6uu8gT1RRxsf4jvyz/xQckiDWd5Sj43dl5AAzdmJGPPFtyQC3haU20H6v09C6whJqSwHDuizT+SW7VFZbWT3jhc+y1bgkYEhbyxHK9hkTGF8hlMk6HSkhAg1vl8t/E7ZcScmh22ZRYXMRijZEEPCgNbDTXDwySqdRnEaLc17z4uvGG/+B2C/60T4aH4VFnFjDyCuIlxCOgMOUM3QcXj0KZakmHxddURpAULfBi00LCamJlJIeUFbnlg3vcrNoCxD/jpHmdZn0jr30jXpgljhAb5AxsX1xwdF5wYROiJTWv6U6nm0A=="
})";

size_t performHandler(void* a1) {
    if (fakeResp == true) {
        fakeResp = false;
        Callback((char*)resp.c_str(), resp.size(), 1, userData);
        std::cout << "[Crack] Faking md5c response" << std::endl;
    }

    if (fakeRespVerInfo == true) {
        fakeRespVerInfo = false;
        Callback((char*)versionInfoResp.c_str(), versionInfoResp.size(), 1, userData);
        std::cout << "[Crack] Faking version info response" << std::endl;
    }
    return 0;
}

int connectWrite() { return 1; }

const std::string readResponse =
R"(HTTP/1.1 200 OK
Content-Length: 64
Connection: close

{"api":"time","code":"1","currentTime": 1718762445577,"msg":""})";
size_t readIdx = 0;
int read(void* a1, void* buf, int numBytes) {
    const auto ret = readResponse.substr(readIdx, numBytes);
    memcpy(buf, ret.c_str(), ret.size());
    readIdx += ret.size();
    return ret.size();
}

typedef HANDLE(WINAPI *CreateRemoteThreadEx_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID,
                                               DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
CreateRemoteThreadEx_t oCreateRemoteThreadEx = nullptr;

void inject(HANDLE proc, const std::string dll) {
    const auto dllAddr = VirtualAllocEx(proc, nullptr, dll.size(), MEM_COMMIT, PAGE_READWRITE);

    if (!dllAddr) {
        std::cout << "Failed to allocate memory for DLL path" << std::endl;
        return;
    }

    if (!WriteProcessMemory(proc, dllAddr, dll.c_str(), dll.size(), nullptr)) {
        std::cout << "Failed to write DLL path into memory" << std::endl;
        return;
    }

    const auto loadLib = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    const auto thread =
        oCreateRemoteThreadEx(proc, nullptr, 0, (PTHREAD_START_ROUTINE)loadLib, dllAddr, 0, nullptr, nullptr);

    if (!thread) {
        std::cout << "Failed to create remote thread" << std::endl;
        return;
    }

    std::cout << "Created remote thread for loading DLL" << std::endl;
}

HANDLE WINAPI createThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
                           LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
                           LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId) {
    if ((int64_t)hProcess != -1) {
        const auto path = std::filesystem::current_path() / "dll.dll";
        inject(hProcess, path.string());
        Sleep(2000);
    }

    return oCreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
                                 dwCreationFlags, lpAttributeList, lpThreadId);
}

void cont()
{
    const auto exe = GetModuleHandle(nullptr);
    const auto header = (PIMAGE_DOS_HEADER)exe;
    const auto nt = (PIMAGE_NT_HEADERS)((uint8_t*)exe + header->e_lfanew);
    const auto size = nt->OptionalHeader.SizeOfImage;

    {
        const void* found = Sig::find(
            exe, size,
            "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 55 41 54 41 55 41 56 41 57 48 8D 6C 24 C9 48 81 EC C0");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, hwid, (LPVOID*)&oHwid);
            MH_EnableHook((LPVOID)found);
        }
    }

    {
        const void* found = Sig::find(exe, size, "89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 85 C9");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, options, (LPVOID*)&oOptions);
            MH_EnableHook((LPVOID)found);
        }
    }

    {
        const void* found = Sig::find(exe, size, "40 55 56 48 83 EC 38 48 8B F1 48 85 C9 75 0A 8D");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, performHandler, NULL);
            MH_EnableHook((LPVOID)found);
        }
    }

    {
        const void* found = Sig::find(exe, size, "40 53 B8 20 00 00 00 E8 64 6F 13 00 48 2B E0 48 83 79 30 00");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, (LPVOID)connectWrite, nullptr);
            MH_EnableHook((LPVOID)found);
        }
    }

    {
        const void* found =
            Sig::find(exe, size, "B8 38 00 00 00 E8 96 55 13 00 48 2B E0 45 85 C0 79 2A BA D0 00 00 00");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, (LPVOID)connectWrite, nullptr);
            MH_EnableHook((LPVOID)found);
        }
    }

    {
        const void* found =
            Sig::find(exe, size, "B8 38 00 00 00 E8 66 5B 13 00 48 2B E0 45 85 C0 79 2A BA DF 00 00 00");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, (LPVOID)read, nullptr);
            MH_EnableHook((LPVOID)found);
        }
    }

    {
        const auto remoteThreadEx = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateRemoteThreadEx");
    	auto res = MH_CreateHook((LPVOID)remoteThreadEx, (LPVOID)createThread, (LPVOID*)&oCreateRemoteThreadEx);
        auto res1 = MH_EnableHook((LPVOID)remoteThreadEx);
    }
}

bool restored = false;
typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
WriteProcessMemory_t oWriteProcessMemory = nullptr;
BOOL WINAPI writeMem(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten) {
    auto result = oWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    const auto ntdll = GetModuleHandle(L"ntdll.dll");
    uint8_t callcode = ((uint8_t*)GetProcAddress(ntdll, "NtQuerySection"))[4] - 1;
    uint8_t restore[] = { 0x4C, 0x8B, 0xD1, 0xB8, callcode };

    volatile auto ntProtectVirtualMemory = (uint8_t*)GetProcAddress(ntdll, "NtProtectVirtualMemory");

    if (restored == false && ntProtectVirtualMemory == lpBaseAddress) {
        DWORD oldProtect;
        VirtualProtect((LPVOID)ntProtectVirtualMemory, sizeof(restore), PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(ntProtectVirtualMemory, restore, sizeof(restore));
        VirtualProtect((LPVOID)ntProtectVirtualMemory, sizeof(restore), oldProtect, nullptr);

        restored = true;

        cont();
    }

    return result;
}

void start() {
    std::cout << "[Crack] Crack loaded, waiting for unpack..." << std::endl;
    MH_Initialize();

    MH_CreateHook((LPVOID)WriteProcessMemory, (LPVOID)writeMem, (LPVOID*)&oWriteProcessMemory);
    MH_EnableHook((LPVOID)WriteProcessMemory);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        const auto thread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)start, nullptr, 0, nullptr);
        DisableThreadLibraryCalls(hinstDLL);
        if (thread) {
            CloseHandle(thread);
        }
    }

    return true;
}