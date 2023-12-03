#include <iostream>
#include <windows.h>

void printError(const char* prefix) {
    DWORD error = GetLastError();
    char buffer[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buffer, sizeof(buffer), NULL);
    std::cout << prefix << ": " << error << ": " << buffer;
    system("pause");
}

const char* exeName = "v1.1.1.0.ex_";
const char* dllPath = "Crack.dll";

int main(int argc, char* argv[]) {
    CHAR exePath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    CHAR* lastSlash = strrchr(exePath, '\\');
    *lastSlash = 0;  // NUL-terminate at the slash
    strcat_s(exePath, MAX_PATH, "\\");
    strcat_s(exePath, MAX_PATH, exeName);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    std::string commandLine = exePath;
    for (int i = 1; i < argc; i++) {
        commandLine += " ";
        commandLine += argv[i];
    }

    if (!CreateProcessA(NULL, const_cast<char*>(commandLine.c_str()), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printError("Failed to create process");
        return 1;
    }

    LPVOID allocatedMemory = VirtualAllocEx(pi.hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!allocatedMemory) {
        printError("Failed to allocate memory");
        return 1;
    }

    if (!WriteProcessMemory(pi.hProcess, allocatedMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        printError("Failed to write process memory");
        return 1;
    }

    LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddress) {
        printError("Failed to get LoadLibraryA address");
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, allocatedMemory, 0, NULL);
    if (!hThread) {
        printError("Failed to create remote thread");
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    VirtualFreeEx(pi.hProcess, allocatedMemory, strlen(dllPath) + 1, MEM_RELEASE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
