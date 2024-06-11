#include <iostream>
#include <filesystem>
#include <windows.h>
#include <codecvt>

void printError(const char* prefix) {
    DWORD error = GetLastError();
    char buffer[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buffer, sizeof(buffer), NULL);
    std::cout << prefix << ": " << error << ": " << buffer;
    system("pause");
}

void inject(HANDLE proc, const std::string dll) {
    const auto dllAddr = VirtualAllocEx(proc, nullptr, dll.size(), MEM_COMMIT, PAGE_READWRITE);

    if (!dllAddr) {
        printError("Failed to allocate memory for DLL path");
        return;
    }

    if (!WriteProcessMemory(proc, dllAddr, dll.c_str(), dll.size(), nullptr)) {
        printError("Failed to write DLL path into memory");
        return;
    }

    const auto loadLib = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    const auto thread =
        CreateRemoteThreadEx(proc, nullptr, 0, (PTHREAD_START_ROUTINE)loadLib, dllAddr, 0, nullptr, nullptr);

    if (!thread) {
        printError("Failed to create remote thread");
        return;
    }

    std::cout << "Created remote thread for loading DLL" << std::endl;
}


std::string exeNamestr = "korepi.exe";
namespace fs = std::filesystem;

int main(int argc, char* argv[]) {

	/*
	std::string exeNamestr;
    const char* exeName = nullptr;
    std::string pattern = ".ex_";
    for (const auto& entry : fs::directory_iterator(fs::current_path())) {
        if (entry.path().extension() == pattern) {
        	exeNamestr = entry.path().filename().string();
            break;
        }
    }
    if (exeNamestr == "") {
        std::cout << "No .ex_ file found in the current directory. " << std::endl;
        system("pause");
        return 1;
    }
    exeName = exeNamestr.c_str();
    CHAR exePath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    CHAR* lastSlash = strrchr(exePath, '\\');
    *lastSlash = 0;  // NUL-terminate at the slash
    strcat_s(exePath, MAX_PATH, "\\");
    strcat_s(exePath, MAX_PATH, exeName);
    */

	std::string commandLine;
    for (int i = 1; i < argc; i++) {
        commandLine += " ";
        commandLine += argv[i];
    }

    
    std::wstring exeNamestrL = std::wstring(exeNamestr.begin(), exeNamestr.end());
    std::wstring commandLineL = std::wstring(commandLine.begin(), commandLine.end());

    SHELLEXECUTEINFO shExecInfo = { 0 };
    shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
    shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	shExecInfo.lpFile = exeNamestrL.c_str();
	shExecInfo.lpDirectory = NULL;
    shExecInfo.nShow = SW_SHOWNORMAL;
	shExecInfo.lpParameters = commandLineL.c_str();
        

    if (!ShellExecuteEx(&shExecInfo)) {
        printError("Failed to start korepi exe");
    }
    else {
        const std::string dll = (std::filesystem::current_path() / "Crack.dll").string();

        inject(shExecInfo.hProcess, dll);

        CloseHandle(shExecInfo.hProcess);
    }

	return 0;
}
