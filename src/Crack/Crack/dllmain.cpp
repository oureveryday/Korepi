#include "pch.h"
#include <winternl.h>
#include <Windows.h>
#include <intrin.h>
#include <polyhook2/Exceptions/BreakPointHook.hpp>

#pragma comment(lib, "ntdll.lib")

//std::shared_ptr<PLH::BreakPointHook> bpHook;
std::string appendstr = "<@/>1<@/>000000000000000000<@/>Crackkkk";

#pragma region Utils

void PrintLog(std::string str)
{
    std::cout << "[";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
    std::cout << "Crack";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED |
        FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout << "] " << str << std::endl;
}

uintptr_t PatternScan(LPCSTR pattern)
{
    static auto pattern_to_byte = [](const char* pattern) {

        auto bytes = std::vector<int>{};

        auto start = const_cast<char*>(pattern);

        auto end = const_cast<char*>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            }
            else {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
        };

    auto mod = GetModuleHandle(NULL);
    if (!mod)
        return 0;
	auto dosHeader = (PIMAGE_DOS_HEADER)mod;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)mod + dosHeader->e_lfanew);
    auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    auto patternBytes = pattern_to_byte(pattern);
    auto scanBytes = reinterpret_cast<std::uint8_t*>(mod);
	auto s = patternBytes.size();
    auto d = patternBytes.data();
    for (auto i = 0ul; i < sizeOfImage - s; ++i) {
        bool found = true;
        for (auto j = 0ul; j < s; ++j) {
            if (scanBytes[i + j] != d[j] && d[j] != -1) {
				found = false;
                break;
            }
        }

        if (found) {
            return (uintptr_t)&scanBytes[i];
        }
    }
    return 0;
}

bool memPatch(uintptr_t address, const std::string& valueStr) {
    std::istringstream iss(valueStr);
    std::string byteStr;
    std::vector<uint8_t> bytes;

    while (iss >> byteStr) {
        uint8_t byte = std::stoul(byteStr, nullptr, 16);
        bytes.push_back(byte);
    }

    DWORD oldProtect;
    if (VirtualProtect(reinterpret_cast<void*>(address), bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        uint8_t* ptr = reinterpret_cast<uint8_t*>(address);
        for (size_t i = 0; i < bytes.size(); ++i) {
            ptr[i] = bytes[i];
        }

        // Restore the protection when done
        DWORD temp;
        VirtualProtect(reinterpret_cast<void*>(address), bytes.size(), oldProtect, &temp);
        return true;
    }
    return false;
}

typedef enum _SECTION_INFORMATION_CLASS {
    SectionBasicInformation,
    SectionImageInformation
} SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;
EXTERN_C NTSTATUS __stdcall NtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS InformationClass, PVOID InformationBuffer, ULONG InformationBufferSize, PULONG ResultLength);
EXTERN_C NTSTATUS __stdcall NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG  NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
EXTERN_C NTSTATUS __stdcall NtPulseEvent(HANDLE EventHandle, PULONG PreviousState);

void DisableVMP()
{
    // restore hook at NtProtectVirtualMemory
    auto ntdll = GetModuleHandleA("ntdll.dll");
    bool linux = GetProcAddress(ntdll, "wine_get_version") != nullptr;
    void* routine = linux ? (void*)NtPulseEvent : (void*)NtQuerySection;
    DWORD old;
    VirtualProtect(NtProtectVirtualMemory, 1, PAGE_EXECUTE_READWRITE, &old);
    *(uintptr_t*)NtProtectVirtualMemory = *(uintptr_t*)routine & ~(0xFFui64 << 32) | (uintptr_t)(*(uint32_t*)((uintptr_t)routine + 4) - 1) << 32;
    VirtualProtect(NtProtectVirtualMemory, 1, old, &old);
}
#pragma endregion

#pragma region Patch1
std::string search1 = "48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 55 41 54 41 55 41 56 41 57";
std::string patch1  = "B0 01 C3 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90";

void Patch1()
{
    PrintLog("Loading memory Patch #1...");

    auto addr = PatternScan(search1.c_str());
    std::stringstream addrss;
    addrss << std::hex << addr;
	std::string addrStr = addrss.str();

    if (addr == 0)
    {
        PrintLog("Failed to find Patch #1 pattern.");
    }
    PrintLog("Address: " + addrStr);
    if (memPatch(addr, patch1))
    {
        PrintLog("Patch #1 success.");
    }
    else
    {
        PrintLog("Patch #1 failed.");
    }
}
#pragma endregion

#pragma region CreateRemoteThreadPatch

bool CreateRemoteThreadPatchEnd = false;
bool CreateRemoteThreadPatchReHook = false;

void HookCreateRemoteThread(_In_ HANDLE hProcess,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ SIZE_T dwStackSize,
    _In_ LPTHREAD_START_ROUTINE lpStartAddress,
    _In_opt_ LPVOID lpParameter,
    _In_ DWORD dwCreationFlags,
    _Out_opt_ LPDWORD lpThreadId)
{
    PrintLog("Triggered hook CreateRemoteThread");
    PrintLog(static_cast<const char*>(lpParameter));
    printf("lpParameter's value is %p \n", lpParameter);

    system("pause");

	const char* str = static_cast<const char*>(lpParameter);


	//std::string crkstr = std::string(str) + appendstr;
	//PrintLog("Replaced String.");
    CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
	PrintLog("Patch finished successfully.");
    //CreateRemoteThreadPatchEnd = true;
    CreateRemoteThreadPatchReHook = true;
}

void CreateRemoteThreadPatch()
{
    auto bpHook = std::make_shared<PLH::BreakPointHook>((uint64_t)&CreateRemoteThread, (uint64_t)&HookCreateRemoteThread);
    bpHook->hook();
	PrintLog("CreateRemoteThread Hook Success.");
    while (!CreateRemoteThreadPatchEnd)
    {
        if (CreateRemoteThreadPatchReHook)
        {
            bpHook->hook();
            CreateRemoteThreadPatchReHook = false;
        }
    }
}
#pragma endregion

#pragma region WriteProcessMemoryPatch

bool WriteProcessMemoryPatchEnd = false;
bool WriteProcessMemoryPatchReHook = false;
int WriteProcessMemoryPatchHookTimes = 1;

void HookWriteProcessMemory(_In_ HANDLE hProcess,
    _In_ LPVOID lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesWritten)
{
    PrintLog("Triggered hook WriteProcessMemory #" + std::to_string(WriteProcessMemoryPatchHookTimes));

    WriteProcessMemoryPatchHookTimes++;

    printf("lpBaseAddress's value is %p \n", lpBaseAddress);
    std::cout << nSize << std::endl;
    if (nSize<10000)
	{
         BYTE* bytePtr = (BYTE*)lpBuffer;

         printf("Hexadecimal contents of lpBuffer:\n");

         for (SIZE_T i = 0; i < nSize; i++) {
             printf("%02x ", bytePtr[i]);
         }

         printf("\n");
         system("pause");
     }
     
	
    const char* str = static_cast<const char*>(lpBuffer);
    WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    PrintLog("Patch finished successfully.");
    //WriteProcessMemoryPatchEnd = true;
    WriteProcessMemoryPatchReHook = true;
}

void WriteProcessMemoryPatch()
{
    auto bpHook = std::make_shared<PLH::BreakPointHook>((uint64_t)&WriteProcessMemory, (uint64_t)&HookWriteProcessMemory);
    bpHook->hook();
    PrintLog("WriteProcessMemory Hook Success.");
    while (!WriteProcessMemoryPatchEnd)
    {
	    if (WriteProcessMemoryPatchReHook)
	    {
            bpHook->hook();
            WriteProcessMemoryPatchReHook = false;
	    }
    }
}
#pragma endregion

#pragma region WaitforExecute
void QueryPerformanceCounterHook(_Out_ LARGE_INTEGER* lpPerformanceCount)
{
    system("pause");
    QueryPerformanceCounter(lpPerformanceCount);
}

void WaitforExecute()
{
    auto bpHook = std::make_shared<PLH::BreakPointHook>((uint64_t)&QueryPerformanceCounter, (uint64_t)&QueryPerformanceCounter);
    bpHook->hook();
    while (bpHook->isHooked());
}
#pragma endregion

void AfterUnpack()
{
    DisableVMP();
	Patch1();
    WriteProcessMemoryPatch();
    CreateRemoteThreadPatch();
}

#pragma region WaitforUnpack

bool WaitforAfterUnpack = true;

void GetSystemTimeAsFileTimeHook(_Out_ LPFILETIME lpSystemTimeAsFileTime)
{
    while (WaitforAfterUnpack);
    GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
}

void WaitforUnpack()
{
    PrintLog("Waiting for unpack...");
    auto bpHook = std::make_shared<PLH::BreakPointHook>((uint64_t)&GetSystemTimeAsFileTime, (uint64_t)&GetSystemTimeAsFileTime);
    bpHook->hook();
    while (bpHook->isHooked());
    PrintLog("Program Unpacked.");
    AfterUnpack();
    WaitforAfterUnpack = false;
}
#pragma endregion

DWORD __stdcall Thread(LPVOID p)
{
    PrintLog("Crack dll Loaded.");
	WaitforUnpack();
	 //CreateRemoteThreadPatch();
	return true;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (hModule)
        DisableThreadLibraryCalls(hModule);

    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        if (HANDLE hThread = CreateThread(nullptr, 0, Thread, hModule, 0, nullptr))
            CloseHandle(hThread);
    }

    return TRUE;
}

extern "C" __declspec(dllexport) void Crack() { return; };