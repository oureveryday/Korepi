﻿#include <Windows.h>
#include <cstdint>
#include <filesystem>
#include <format>
#include <vector>
#include "veh_hooks.h"
#include "macros.h"
#include "keyauth_helpers.h"
#include "MinHook.h"
#include "Logger.h"
#include "injector.h"
#include <fstream>
#include <cinttypes>
#include "util.h"

// well-known sigs
#define KACTR "40 53 55 56 57 41 54 41 56 41 57 48 83 EC ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 49 8B F1"
#define SYSERR_SIG "48 89 5C 24 ? 57 48 83 EC ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 48 8B DA 48 8B F9"
#define KEYAUTH_INIT_SIG "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 54 41 55 41 56 41 57 48 8D AC 24 90 FB FF FF"
#define LIMIT 3

#pragma comment(lib, "ntdll.lib")


#pragma region("minty")
void *o_alert;

int32_t *alert(int32_t arg1, char arg2, int32_t arg3, const char *arg4) {
//    return ORIG(alert, arg1, arg2, arg3, arg4);
    return ORIG(alert, arg1, 1, 60000, "CrackPipe says hi!");
}

void *o_minty_inject;

int64_t *minty_inject(HANDLE target, const char *path) {
    char our_dll[260];
    HMODULE hm = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCSTR>(&minty_inject), &hm);
    GetModuleFileNameA(hm, our_dll, 260);
    LOG("Injecting along with Minty.\n");
    ORIG(minty_inject, target, path);
    ORIG(minty_inject, target, our_dll);
    unhook_and_leave();
    return 0;
}

void *o_check_license;

int64_t check_license() {
    SUC("Skipping license check.\n");
    unhook_and_leave();
    return 69;
}

void *o_keyauth_get;

char **keyauth_get(char **out, void **post_data, void **url) {
    LOG("POST secrets: %s\n", static_cast<char *>(*post_data));
    LOG("URL: %s\n", static_cast<char *>(*url));
    const auto result = ORIG(keyauth_get, out, post_data, url);
    LOG("Response: %s\n", *result);
    return result;
}

void *o_ka_init;

void ka_init(api *arg1) {
    api *api = arg1;
//    api* api = reinterpret_cast<struct api*>((uint64_t)arg1 + 0x8d0);
    LOG("Name: %s, Owner: %s, Secret: %s, Version: %s, URL: %p\n", api->name.c_str(), api->ownerid.c_str(),
        api->secret.c_str(),
        api->version.c_str(), api->url.c_str());
    if (api->url.c_str() != nullptr) {
#ifdef LOCAL
        const std::string new_url("http://127.0.0.1/api/1.2/");
#else
        const std::string new_url("https://crackpipe.notmarek.com/api/1.2/");
#endif
        api->url = new_url;
    }
    ORIG(ka_init, arg1);
    unhook_and_leave();
}

void *o_system_error;

int64_t system_error(int64_t a, int64_t b) {
    SUC("Bypassing auth ;)\n");
    unhook_and_leave();
    return 1;
}

void *o_ka_constructor;

int64_t *ka_constructor(api *arg1, someKindaString name, someKindaString ownerid, someKindaString secret,
                        someKindaString version, someKindaString url) {
    LOG("Name: %s, Owner: %s, Secret: %s, Version: %s, URL: %s\n", name.c_str(), ownerid.c_str(), secret.c_str(),
        version.c_str(), url.c_str());
#ifdef LOCAL
    const std::string new_url("http://127.0.0.1/api/1.2/");
#else
    const std::string new_url("https://crackpipe.notmarek.com/api/1.2/");
#endif
    url = new_url;
    auto result = ORIG(ka_constructor, arg1, name, ownerid, secret, version, url);
    unhook_and_leave();
    return result;
}

void *hook_exported(const char *module_name, const char *proc_name, void *detour) {
    const HMODULE handle = GetModuleHandleA(module_name);
    if (!handle) {
        ERR("Couldn't hook %s::%s", module_name, proc_name);
        return nullptr;
    }
    const auto found = reinterpret_cast<void **>(GetProcAddress(handle, proc_name));
    void *orig;
    DBG("Found %s:%s @ %p\n", module_name, proc_name, found); \
    MH_STATUS result = MH_CreateHook((LPVOID) found, (void *) detour, (LPVOID *) &orig); \
    DBG("MH_CreateHook result: %s\n", MH_StatusToString(result)); \
    result = MH_EnableHook((LPVOID) found); \
    DBG("MH_EnableHook result: %s\n", MH_StatusToString(result)); \
    return orig;
}

#pragma endregion

#pragma region("korepi")
void *o_CreateRemoteThreadEx_hk;

HANDLE WINAPI CreateRemoteThreadEx_hk(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
                                      LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
                                      LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId);

void inject_into_genshin(HANDLE proc, const std::string dll) {
    const auto dllAddr = VirtualAllocEx(proc, nullptr, dll.size(), MEM_COMMIT, PAGE_READWRITE);

    if (!dllAddr) {
        ERR("Failed to allocate memory for DLL path\n");
        return;
    }

    if (!WriteProcessMemory(proc, dllAddr, dll.c_str(), dll.size(), nullptr)) {
        ERR("Failed to write DLL path into memory\n");
        return;
    }

    const auto loadLib = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    const auto thread =
            ORIG(CreateRemoteThreadEx_hk, proc, nullptr, 0, (PTHREAD_START_ROUTINE) loadLib, dllAddr, 0, nullptr,
                 nullptr);

    if (!thread) {
        ERR("Failed to create remote thread\n");
        return;
    }
    SUC("Created remote thread for loading DLL\n");
}

HANDLE WINAPI CreateRemoteThreadEx_hk(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
                                      LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
                                      LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId) {
    if ((int64_t) hProcess != -1) {
        LOG("CreateRemoteThreadEx\n");

        char our_dll[260];
        HMODULE hm = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCSTR>(&minty_inject), &hm);
        GetModuleFileNameA(hm, our_dll, 260);
        inject_into_genshin(hProcess, our_dll);
//        Sleep(2000);
    }

    return ORIG(CreateRemoteThreadEx_hk, hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
                dwCreationFlags, lpAttributeList, lpThreadId);
}

void *o_write_process_memory;

BOOL __stdcall write_process_memory(
        const HANDLE a,
        const LPVOID b,
        const LPCVOID c,
        const SIZE_T d,
        SIZE_T *e
);

void *o_krpi_hwid;

char **krpi_hwid(char **hwid_out) {
    int i = 0;
    auto result = ORIG(krpi_hwid, hwid_out);
    LOG("Hwid: %s\n", *hwid_out);
    const auto s = std::string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    memcpy(*hwid_out, s.c_str(), s.size() + 1);
    remove_hooks();
    MH_Initialize();
    API_HOOK("kernel32.dll", "CreateRemoteThreadEx", CreateRemoteThreadEx_hk);
    API_HOOK("kernel32.dll", "WriteProcessMemory", write_process_memory);
    return result;
}



void *o_manual_map_dll;


void *manual_map_dll(HANDLE proc, void *dll, int64_t size, void **data) {
    HMODULE hm = GetModuleHandleA(nullptr);
    char module_path[260];
    GetModuleFileNameA(hm, module_path, 260);
    std::string path = std::filesystem::path(module_path).parent_path().string();
    replace_all(path, "\\", "\\\\");

    std::string i_want_to_be_cool_when_i_grow_up = std::format(
            "{{\"path\":\"{}\",\"discordId\":\"69\",\"secret_extra\":\"frAQBc8W\",\"isEnterDoorLoad\":\"true\"}}",
            path.c_str());

//    LOG("Data: %s = %s\n", (char*)(*secrets), i_want_to_be_cool_when_i_grow_up.c_str());
    char our_dll[260];
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCSTR>(&minty_inject), &hm);
    GetModuleFileNameA(hm, our_dll, 260);
    memcpy(*(char **) data, i_want_to_be_cool_when_i_grow_up.c_str(), i_want_to_be_cool_when_i_grow_up.length() + 1);
    auto result = ORIG(manual_map_dll, proc, dll, size, data);
    std::ifstream infile(our_dll);
    infile.seekg(0, std::ios::end);
    size_t length = infile.tellg();
    infile.seekg(0, std::ios::beg);
    char buffer[10000];
    infile.read(buffer, length);
//    auto result = ORIG(manual_map_dll, proc, (void*)buffer, length, secrets);
//    LOG("resut:%p\n", result);
    inject(proc, our_dll);
    return result;
}

void *o_return_true;

uint64_t return_true() {
    return 1;
}

void *o_read;
const std::string readResponse =
        R"(HTTP/1.1 200 OK
Content-Length: 64
Connection: close

{"api":"time","code":"1","currentTime": 1718762445577,"msg":""})";
size_t readIdx = 0;

size_t read(void *a1, void *buf, int numBytes) {
//    return ORIG(read, a1, buf, numBytes);
    const auto ret = readResponse.substr(readIdx, numBytes);
    memcpy(buf, ret.c_str(), ret.size());
    readIdx += ret.size();
    return ret.size();
}

bool fakeResp = false;
bool fakeVer = false;
const std::string verinfo = R"|({
    "msg": "success",
    "code": 200,
    "data": {
        "announcement": "4.6 os&cn",
        "latest_version": "1.3.1.3",
        "update_required": true,
        "update_url": "https://github.com/Cotton-Buds/calculator/releases",
        "updated_at": "2024-05-16 03:21",
        "updated_by": "Strigger(main) & Micah(auth) & EtoShinya(tech)",
        "update_diff": {
            "added_features": [
                "fix all 409",
                "Fix camera issues"
            ],
            "deleted_features": [
                "�޸�����ʧЧ����",
                "Restore all malfunctioning features."
            ],
            "total_size": "78.0 MB"
        },
        "compatible_versions": [
            "none"
        ]
    },
    "sign2": "LQuoFI+EQmj+ET67geipuHkfY0OlqPjefO4JftDJEIGZbKhV66kl8RGB4ANTHARYjmCo9OokSqTzkRJMVFyb2hM/ichoegIDsuEFtTlkR3uBmZUI43kyOHOfIEh3EWOY689RXKDGpjd20EIHDQUw7dRiAwUah9HjZG/hit1gM71d0Eqd2juhP2lMsvMn2R/F3xemK+DfOLvddzhosZyRF3p2oDlgWS7y821qbch1aMBNMFqajCHc/C3sxgkIEglHajep4+UhOhxHpeDHEhn+OX33ULVNu/+6S0FVi8J39L/xua/ACfA57KfWdSidwAZYU5rtB/sM6piXhbNUGK2wdA=="
})|";
const std::string resp = R"({"msg": "AtZAfcAb+qtSipkXI9CP8u5XUYPGyCbGq5C/VYyt6tcelFYehMuYs0q8m/q+RwGx0/jOB3jDRAqjcqmunJpoKrIFV9W/YC9wzY+GaSU2L8oNQHlpx9KgJ0K50aqwxQD0dKiWmd16b76sLCn8GvpVrSk1k6SoFtUtPe30Cf1BkOsFD2oxSGBioUK22MkPFO2uj5xIXfZ5tC1dB4cS5ttzVlDiLPXY1hlJBqgFpZTj8znRz5qpMhflK5euefmKRPTKzwt+JHFF2YImsmDf49bMCgS6ZIwHL/jbK8dRJwFRjfkZjvpw2XxrL3wKubLqZKjUG3lHP6oKijmcWFTeu68xHphRKmqy43Gg3MZ1wCoYwcQL6tPPoqMy6TJwJdt/mBfhklPRq0XcTAjpnTIJeIo7zH/L1kFaGRAVFtqbwGLIIN08bb+7/tV3MOOc8BEp4RCb721hakBRNFqJAeYrt7yzr/VeK2igLuByrTcBkd0SOIB5LgI5K/qrMf/90bB8sfcicIgJXSVxyuuov45UXM2Rdo4YiL5M8b4LCJwhEkmplS8=", "code": 200})";
const std::string oldresp =
R"({
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

void *o_curl_easy_perform;
void *userData;

typedef size_t (*callback_t)(char *ptr, size_t size, size_t nmemb, void *userdata);

callback_t callback = nullptr;
bool old_launcher = true;

size_t curl_easy_perform(void *a1) {
    if (fakeVer) {
        LOG("Serving fake versions info.\n");
        fakeVer = false;
        callback((char *) verinfo.c_str(), verinfo.size(), 1, userData);
        LOG("Served fake versions info.\n");
        return 0;
    } else if (fakeResp && old_launcher) {
        LOG("Serving fake sub info.\n");
        fakeResp = false;
        callback((char *) oldresp.c_str(), oldresp.size(), 1, userData);
        return 0;
    } else if (fakeResp) {
        LOG("Serving fake sub info.\n");
        fakeResp = false;
        callback((char *) resp.c_str(), resp.size(), 1, userData);
        return 0;
    }
    return ORIG(curl_easy_perform, a1);
}

void *o_curl_easy_setopt;

void curl_easy_setopt(void *a1, size_t a2, void *a3) {
    if (a2 == 0x2712) { // CURLOPT_URL
        if (memcmp(a3, "https://ghp.", 12) == 0) {
            fakeVer = true;
        } else if (memcmp(a3, "https://md5c.", 12) == 0) {
            fakeResp = true;
        }
    }
    if (a2 == 0x2711) { // CURLOPT_WRITEDATA
        userData = a3;
    }
    if (a2 == 0x4e2b) { // CURLOPT_WRITEFUNCTION
        callback = (callback_t) a3;
    }
    ORIG(curl_easy_setopt, a1, a2, a3);
}

const auto* pubKey = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0SxoW83nU4qAbHXqjhal\n"
"MiU62ae79Ayv/EAmVfJEeCymJIpvtTqoPr99MBMDMHPxqqW1TgapD0bdAoU0vBpx\n"
"G5INKIQnVi1ZE0YPP1GKUXN4nchM31a9NqG4mdWXtpD/jTt40Tpxn/zaj/5kDCuP\n"
"o+iKQqwzKnE27Fyi0USLK82PfwCN0KlA4hmHUgB0UD+eG3VSlfHuU4ZITKqwEZFy\n"
"wREoekljDot8noMOQiBo0NgqmkLLK2WQ2TaTSm3A/E6d7FI+HrdPdl/GmMdTF1tf\n"
"lr1yMFQ1eAdOJqnmM5YxCv4FsU2qpZFFXNEbnjJ+mx549LMUWBUeRjOwZ8zXUWxd\n"
"oQIDAQAB\n"
"-----END PUBLIC KEY-----";
bool replacedPubKey = false;

void *o_copy = nullptr;

size_t copy(void *a1, const char *a2) {
    if (memcmp(a2, "Strigger(main) & Micah(auth) & EtoShinya(update)", 48) == 0) {
        a2 = "Fadz(crack) & Strigger(bitch) & Micah(auth) & EtoShinya(update)";
    } else if (memcmp(a2, "4.8 os&cn", 9) == 0) {
        a2 = "CrackPipe!~";
    } else if (memcmp(a2, "2024-07-24 00:21", 16) == 0) {
        a2 = "Never lol";
    } else if (memcmp(a2, "-----BEGIN PUBLIC KEY-----", 26) == 0 && replacedPubKey == false) {
        LOG("Replaced public key.\n");
        replacedPubKey = true;
        a2 = pubKey;
    }

    return ORIG(copy, a1, a2);
}

void *o_strtoimax_hk;

int64_t strtoimax_hk(int64_t *arg1) {
    DBG("strtoimax_hk\n");
    if (memcmp("172196878339", arg1, 12))
        return 0x1f0ed5537a7;
    return ORIG(strtoimax_hk, arg1);
}

bool init = false;
bool dll_dumped = false;
bool unpacked = false;
bool hooked = false;

BOOL __stdcall write_process_memory(
        const HANDLE a,
        const LPVOID b,
        const LPCVOID c,
        const SIZE_T d,
        SIZE_T *e
) {
    int i = 0;
    if (!init) {
        MEMORY_BASIC_INFORMATION mbi;
        bool foundBase = false;
        const auto expectedRegion = 0x3d3000;
        char *base = nullptr;

        while (!foundBase) {
            base = nullptr;
            while (VirtualQuery(base, &mbi, sizeof(mbi)) == sizeof(MEMORY_BASIC_INFORMATION)) {
                if (mbi.RegionSize == expectedRegion) {
                    foundBase = true;
                    break;
                }

                base += mbi.RegionSize;
            }
        }
        bypass_vmp();
        HOOK_IF_FOUND_MANUAL((uint8_t *) base, expectedRegion, "curl_easy_setopt",
                             "89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 85 C9",
                             curl_easy_setopt);
        HOOK_IF_FOUND_MANUAL((uint8_t *) base, expectedRegion, "curl_easy_perform",
                             "40 55 56 48 83 EC 38 48 8B F1 48 85 C9 75 0A 8D", curl_easy_perform);
        MH_CreateHook((void *) strtoimax, strtoimax_hk, &o_strtoimax_hk);
        MH_EnableHook((void *) strtoimax);
        init = true;
//        HOOK_IF_FOUND(nullptr, "HWID", "48 89 5C 24 10 48 89 7C 24 18 55 48 8D 6C", krpi_hwid);
//        if (!o_krpi_hwid) {
//            return ORIG(write_process_memory, a, b, c, d, e);
//        }
//        HOOK_IF_FOUND(nullptr, "copy", "40 53 48 83 EC 20 33 C0 0F 57 C0 0F 11 01 48 89 41 10 48 8B D9 48 89 41 18 49 C7 C0 FF FF FF FF 49 FF C0 42", copy);
//        HOOK_IF_FOUND(nullptr, "curl_easy_setopt", "89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 85 C9",
//                      curl_easy_setopt);
//        HOOK_IF_FOUND(nullptr, "curl_easy_perform", "40 55 56 48 83 EC 38 48 8B F1 48 85 C9 75 0A 8D", curl_easy_perform);
//        HOOK_IF_FOUND(nullptr, "connectWrite", "40 53 B8 20 00 00 00 E8 ?? ?? ?? ?? 48 2B E0 48 83 79 30 00", return_true);
//        HOOK_IF_FOUND(nullptr, "connectWrite2", "B8 38 00 00 00 E8 ?? ?? ?? ?? 48 2B E0 45 85 C0 79 2A BA D0 00 00 00", return_true);
//        HOOK_IF_FOUND(nullptr, "read", "B8 38 00 00 00 E8 ?? ?? ?? ?? 48 2B E0 45 85 C0 79 2A BA DF 00 00 00", read);
    } else if (d == 0x1000 && !dll_dumped) {
        const auto p_src_data = static_cast<const BYTE *>(c);
        auto p_nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(p_src_data +
                                                                       reinterpret_cast<const IMAGE_DOS_HEADER *>(p_src_data)->e_lfanew);
        const auto p_optional_header = &p_nt_headers->OptionalHeader;
        const auto p_first_section_header = IMAGE_FIRST_SECTION(p_nt_headers);
        const auto p_last_section_header = p_first_section_header + (p_nt_headers->FileHeader.NumberOfSections - 1);
        auto dll_size = p_last_section_header->PointerToRawData + p_last_section_header->SizeOfRawData;
        DBG("Found Korepi DLL: ImageSize: %p, LastSectionRawData*: %p, LastSectionRawDataSize: %p, ActualSizeOnDisk: %p\n",
            p_optional_header->SizeOfImage, p_last_section_header->PointerToRawData,
            p_last_section_header->SizeOfRawData,
            p_last_section_header->PointerToRawData + p_last_section_header->SizeOfRawData);
        if (const std::filesystem::path dll_dump_path = (std::filesystem::current_path() / "korepi.dll"); !dll_dumped) {
            dll_dumped = true;
            LOG("Dumping dll to file.\n");
            std::fstream out(dll_dump_path, std::ios::binary | std::ios::out);
            out.write(reinterpret_cast<const char *>(c), dll_size);
            LOG("DLL written have fun reversing. :)\n");
            out.close();
        }
    }

    return ORIG(write_process_memory, a, b, c, d, e);
};
//void *o_spawn_genshin;
//
//uint64_t spawn_genshin(HANDLE *handle, HANDLE *thread) {
//
//    auto result = ORIG(spawn_genshin, handle, thread);
//    HMODULE mod = GetModuleHandleA(nullptr);
//    HRSRC hResInfo = FindResourceA(mod, "BIN", MAKEINTRESOURCEA(RT_RCDATA));
//    HGLOBAL hResData;
//    if (hResInfo != 0)
//        hResData = LoadResource(mod, hResInfo);
//    int64_t size = SizeofResource(mod, hResInfo);
//    void *dll = LockResource(hResData);
//
//    void *datadd = (void *) malloc(500 * sizeof(char));
//    manual_map_dll(handle, dll, size, &datadd);
//
//    return result;
//}


void* o_GetSystemTimeAsFileTime_hk;
int hooknum = 0;
const int tohooknum = 0;
void GetSystemTimeAsFileTime_hk(_Out_ LPFILETIME lpSystemTimeAsFileTime)
{
    DBG("GetSystemTimeAsFileTime_hk\n");
    if (hooknum < tohooknum)
    {
	    hooknum++;
		return ORIG(GetSystemTimeAsFileTime_hk, lpSystemTimeAsFileTime);
    }
    unpacked = true;
    
    while (!hooked);
    DBG("GetSystemTimeAsFileTime Resume\n");
    return ORIG(GetSystemTimeAsFileTime_hk, lpSystemTimeAsFileTime);
}
#pragma endregion

void start() {
    int i = 0;
    HMODULE hm = GetModuleHandleA(nullptr);
    char module_path[260];
    GetModuleFileNameA(hm, module_path, 260);
    std::string module_path_str = std::string(module_path);

    if (module_path_str.ends_with("rundll32.exe")) return;
    INIT_LOGGER("CrackPipe", RGB(74, 255, 155), RGB(35, 173, 252), RGB(252, 35, 60), RGB(71, 245, 103));
    g_logger.ColorPrint("                    ..."
                        "\n                   ;::::;"
                        "\n                 ;::::; :;"
                        "\n               ;:::::'   :;"
                        "\n              ;:::::;     ;."
                        "\n             ,:::::'       ;           OOO\\"
                        "\n             ::::::;       ;          OOOOO\\"
                        "\n             ;:::::;       ;         OOOOOOOO"
                        "\n            ,;::::::;     ;'         / OOOOOOO"
                        "\n          ;:::::::::`. ,,,;.        /  / DOOOOOO"
                        "\n        .';:::::::::::::::::;,     /  /     DOOOO"
                        "\n       ,::::::;::::::;;;;::::;,   /  /        DOOO"
                        "\n      ;`::::::`'::::::;;;::::: ,#/  /          DOOO"
                        "\n      :`:::::::`;::::::;;::: ;::#  /            DOOO"
                        "\n      ::`:::::::`;:::::::: ;::::# /              DOO"
                        "\n      `:`:::::::`;:::::: ;::::::#/               DOO"
                        "\n       :::`:::::::`;; ;:::::::::##                OO"
                        "\n       ::::`:::::::`;::::::::;:::#                OO"
                        "\n       `:::::`::::::::::::;'`:;::#                O"
                        "\n        `:::::`::::::::;' /  / `:#"
                        "\n         ::::::`:::::;'  /  /   `#\n", 0xd | FOREGROUND_INTENSITY);
    MH_STATUS status = MH_Initialize();
    LOG("Initialized MinHook: %s\n", MH_StatusToString(status));
    if (module_path_str.ends_with("GenshinImpact.exe")) {
        LOG("We are inside Genshin!\n");
        
        API_HOOK("kernel32.dll", "GetSystemTimeAsFileTime", GetSystemTimeAsFileTime_hk);
        LOG("Waiting for unpack...\n");
        while (!unpacked);
        LOG("Program unpacked.\n");
        MH_DisableHook(MH_ALL_HOOKS);
        MH_RemoveHook(MH_ALL_HOOKS);
//        API_HOOK("kernel32.dll", "WriteProcessMemory", write_process_memory);
//
        MEMORY_BASIC_INFORMATION mbi;
        bool foundBase = false;
        const auto expectedRegion = 0x39D5000;
        char* base = nullptr;
        while (!foundBase) {
            base = nullptr;
            while (VirtualQuery(base, &mbi, sizeof(mbi)) == sizeof(MEMORY_BASIC_INFORMATION)) {
                if (mbi.RegionSize == expectedRegion) {
                    foundBase = true;
                    break;
                }
                base += mbi.RegionSize;
            }
        }
        bypass_vmp();
        HOOK_IF_FOUND_MANUAL((uint8_t *) base, expectedRegion, "curl_easy_setopt",
                             "89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 85 C9",
                             curl_easy_setopt);
//        API_HOOK("comdlg32.dll", "GetOpenFileNameW", GetOpenFileNameW_hk);
        HOOK_IF_FOUND_MANUAL((uint8_t *) base, expectedRegion, "curl_easy_perform",
                             "40 55 56 48 83 EC 38 48 8B F1 48 85 C9 75 0A 8D", curl_easy_perform);
        HOOK_IF_FOUND_MANUAL((uint8_t*)base, expectedRegion, "copy", "40 53 48 83 EC 20 33 C0 0F 57 C0 0F 11 01 48 89 41 10 48 8B D9 48 89 41 18 49 C7 C0 FF FF FF FF 49 FF C0 42", copy);
        hooked = true;
        return;
    };

    LoadLibraryA("Kernel32.dll");
    LoadLibraryA("ntdll.dll");
    LoadLibraryA("ucrtbase.dll");
    LoadLibraryA("VCRUNTIME140.dll");
    LoadLibraryA("MSVCP140.dll");
    LoadLibraryA("api-ms-crt-stdio-l1-1-0.dll");
    LoadLibraryA("api-ms-crt-runtime-l1-1-0.dll");
    LoadLibraryA("api-ms-crt-heap-l1-1-0.dll");
    LoadLibraryA("api-ms-crt-convert-l1-1-0.dll");

    HOOK_IF_FOUND_AND(nullptr, "Inject",
                      "40 53 55 56 57 41 56 48 83 EC ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 48 8B E9", minty_inject)
            return; }
        i = 0;
    }
    VehUtils::veh_hooks = std::vector<VehHook>();
    VehUtils::bypass_addrs = std::vector<void *>();
    bool was_vmp_bypassed = bypass_vmp();
//    API_HOOK("kernel32.dll", "LoadResource", loadrsrc);
//    API_HOOK("kernel32.dll", "LockResource", lockrsrc);
    if (module_path_str.ends_with("korepi.exe")) {
        old_launcher = true;
//        HOOK_IF_FOUND(nullptr, "HWID", "48 89 5C 24 10 48 89 7C 24 18 55 48 8D 6C", krpi_hwid);
//        if (!o_krpi_hwid) {
//            return ORIG(write_process_memory, a, b, c, d, e);
//        }
//        HOOK_IF_FOUND(nullptr, "copy", "40 53 48 83 EC 20 33 C0 0F 57 C0 0F 11 01 48 89 41 10 48 8B D9 48 89 41 18 49 C7 C0 FF FF FF FF 49 FF C0 42", copy);

//        HOOK_IF_FOUND(nullptr, "spawn_genshin", "48 8B C4 48 89 58 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D A8 88 FE FF FF", spawn_genshin)
        HOOK_IF_FOUND(nullptr, "manual_map", "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 F0 BF FF FF",
                      manual_map_dll);
        HOOK_IF_FOUND(nullptr, "curl_easy_setopt", "89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 85 C9",
                      curl_easy_setopt);
        HOOK_IF_FOUND(nullptr, "curl_easy_perform", "40 55 56 48 83 EC 38 48 8B F1 48 85 C9 75 0A 8D",
                      curl_easy_perform);
        HOOK_IF_FOUND(nullptr, "Logger", "4C 89 4C 24 ? 55 53 56 57 41 54", return_true);
        HOOK_IF_FOUND(nullptr, "connectWrite", "40 53 B8 20 00 00 00 E8 ?? ?? ?? ?? 48 2B E0 48 83 79 30 00",
                      return_true);
        HOOK_IF_FOUND(nullptr, "connectWrite2", "B8 38 00 00 00 E8 ?? ?? ?? ?? 48 2B E0 45 85 C0 79 2A BA D0 00 00 00",
                      return_true);
        HOOK_IF_FOUND(nullptr, "read", "B8 38 00 00 00 E8 ?? ?? ?? ?? 48 2B E0 45 85 C0 79 2A BA DF 00 00 00", read);
//        API_HOOK("kernel32.dll", "CreateRemoteThreadEx", CreateRemoteThreadEx_hk);

        return;
    } else if (module_path_str.ends_with("korepi.exe")) {
        API_HOOK("kernel32.dll", "WriteProcessMemory", write_process_memory);

    } else {
        g_vehUtils.Init();
        SUC("Registered VEH for VMP CRC check bypass and/or VEH hooks: %p\n", g_vehUtils.handler);

    }


//    HOOK_IF_FOUND("MintyZZZ.dll", "system_error", SYSERR_SIG, check_license)
    HOOK_IF_FOUND("MintyZZZ.dll", "Alert", "4C 89 4C 24 ? 53 56 57 48 83 EC ? 41 8B F8", alert);

    HOOK_IF_FOUND("MintyZZZ.dll", "system_error ", SYSERR_SIG, system_error)
    HOOK_IF_FOUND("MintyZZZ.dll", "KeyAuth constructor", KACTR, ka_constructor)
    HOOK_IF_FOUND("MintyZZZ.dll", "KeyAuth init", KEYAUTH_INIT_SIG, ka_init)
    HOOK_IF_FOUND("MintyZZZ.dll", "ZZZ check license", "41 50 49 B8 87 75 82 25 D2 6D 26 72", check_license)
/// as many normal hooks as you want
    HOOK_IF_FOUND("MintyWW.dll", "Alert", "4C 89 4C 24 ? 53 56 57 48 83 EC ? 41 8B F8", alert);
    HOOK_IF_FOUND("MintyWW.dll", "system_error", SYSERR_SIG, system_error)
    if (o_system_error != nullptr) return;
    HOOK_IF_FOUND("MintyWW.dll", "KeyAuth constructor", KACTR, ka_constructor)
    if (o_ka_constructor != nullptr) return;
    HOOK_IF_FOUND("MintyWW.dll", "KeyAuth init", KEYAUTH_INIT_SIG, ka_init)
    if (o_ka_init != nullptr) return;

/// only ONE veh hook per process -> if there are more in this case a few get called around the time we are unhooking --- fucking up the rest and crashing!!~
    HOOK_IF_FOUND("Revamp.dll", "Alert", "4C 89 4C 24 ? 53 56 57 48 83 EC ? 41 8B F8", alert)
    VEH_HOOK_IF_FOUND("Revamp.dll", "system_error", SYSERR_SIG, system_error)
    if (o_system_error != nullptr) return;
    VEH_HOOK_IF_FOUND("Revamp.dll", "KeyAuth constructor", KACTR, ka_constructor)
    if (o_ka_constructor != nullptr) return;
    VEH_HOOK_IF_FOUND("Revamp.dll", "KeyAuth init",
                      "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 54 41 55 41 56 41 57 48 8D AC 24 90 FB FF FF",
                      ka_init)
    if (o_ka_init != nullptr) return;


}

extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        const auto thread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE) start, nullptr, 0, nullptr);
        DisableThreadLibraryCalls(hinstDLL);
        if (thread) {
            CloseHandle(thread);
        }
    }

    return true;
}
