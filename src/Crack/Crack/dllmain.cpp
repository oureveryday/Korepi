#include "pch.h"
#include <polyhook2/Exceptions/BreakPointHook.hpp>

extern "C" void SetR9Register(const char* str);
bool waitforPatch = true;
int hookTimes = 1;
std::shared_ptr<PLH::BreakPointHook> bpHook;
std::string appendstr = "<@/>1<@/>000000000000000000<@/>Crackkkk";

void Hook(_In_ HANDLE hProcess,
    _In_ LPVOID lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesWritten)
{
    std::cout << "[Crack] Triggered hook #" << hookTimes <<std::endl;
    if (hookTimes == 2)
    {
        const char* str = static_cast<const char*>(lpBuffer);
        std::string crkstr = std::string(str) + appendstr;
        std::cout << "[Crack] Replaced String." << std::endl;
        WriteProcessMemory(hProcess, lpBaseAddress, (LPCVOID)crkstr.c_str(), nSize+appendstr.length(), lpNumberOfBytesWritten);
        waitforPatch = false;
        return;
    }
    WriteProcessMemory(hProcess,lpBaseAddress,lpBuffer,nSize,lpNumberOfBytesWritten);
    hookTimes += 1;
    bpHook->hook();
}

DWORD __stdcall Thread(LPVOID p)
{
    std::cout << "[Crack] Loading..." << std::endl;
    bpHook = std::make_shared<PLH::BreakPointHook>((uint64_t)&WriteProcessMemory, (uint64_t)&Hook);
    bpHook->hook();
	std::cout << "[Crack] Hook Success." << std::endl;

    while (waitforPatch);
    std::cout << "[Crack] Patched successfully." << std::endl;
    return TRUE;
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