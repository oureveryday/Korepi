#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>

void RunExe(const char* cmdline) {
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;

    size_t len = strlen(cmdline) + 1;
    wchar_t* w_cmdline = new wchar_t[len];

    size_t out_len;
    mbstowcs_s(&out_len, w_cmdline, len, cmdline, len - 1);

    if (CreateProcessW(NULL, w_cmdline, NULL, NULL,
        FALSE, 0, NULL, NULL, &si, &pi)) {
        return;
    }
    else {
        std::cout << "Failed to run command " << cmdline << ", error: " << GetLastError() << std::endl;
    }

    delete[] w_cmdline;
}

std::string GetCurrentWorkingDir() {
    char current_dir[MAX_PATH];
    if (!GetCurrentDirectoryA(MAX_PATH, current_dir)) {
        std::cerr << "Error getting current directory: #" << GetLastError();
    }
    return std::string(current_dir);
}


int main() {
    std::string data_string = GetCurrentWorkingDir() + "<@/>1<@/>000000000000000000<@/>Crackkkk";
    std::string file = "Baymax64.Ini";
    std::string patcher = "Patch.ex_";

    int size = data_string.size() + 1;

    SetFileAttributesA(file.c_str(), FILE_ATTRIBUTE_NORMAL);

    if (std::ifstream(file))
        std::remove(file.c_str());

    std::ofstream ofs(file);
    if (!ofs) {
        std::cout << "Failed to open file\n";
        return -1;
    }
    ofs << "[BAYMAX64]" << "\n";
    ofs << "DATA = " << data_string << "\n";
    ofs << "SIZE = " << size << "\n";
    ofs.close();

    SetFileAttributesA(file.c_str(), FILE_ATTRIBUTE_READONLY);

    RunExe(patcher.c_str());

    return 0;
}
