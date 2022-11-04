#define _CRT_SECURE_NO_WARNINGS

#include "Hijack.h"
#include "minhook/include/MinHook.h"
#include "PatternScan.h"
#include <intrin.h>
#include <unordered_map>
#include <algorithm>

void* o_CreateFileW = nullptr;

std::wstring FindFileName(std::wstring fileName)
{
    wchar_t* last = (wchar_t*)wcsstr(fileName.c_str(), L"\\");
    while (true)
    {
        if (wcsstr(last + 1, L"\\") == NULL)
        {
            break;
        }
        last = wcsstr(last + 1, L"\\");
    }
    std::wstring ret = std::wstring(last + 1);
    ret.resize(ret.size() - 4); // 不需要文件结尾格式
    return ret;
}


struct finfo
{
    void* ptr;
    size_t size;
    finfo(void* ptr1, size_t sz) : ptr(ptr1), size(sz)
    {

    }
    finfo()
    {
        ptr = nullptr;
        size = 0;
    }
};

std::unordered_map<std::wstring, finfo> FileInfo;

HANDLE WINAPI hk_CreateFileW(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
)
{
    // CreateFileA/W都会被调用，但是似乎主要使用CreateFileW，所以我们hook这个函数

    // mp3写入
    static void* retaddr = Utils::PatternScan(GetModuleHandleA("cloudmusic.dll"), "8B C8 EB 38 E8 ? ? ? ? 83 78 10 00 74 2A 8D 4D 08 E8 ? ? ? ? 83 78 14 10 72 02 8B 00 6A 00 6A 00");
    // ncm写入
    static void* retaddr1 = Utils::PatternScan(GetModuleHandleA("cloudmusic.dll"), "89 45 AC 83 F8 FF 75 11 FF 15 ? ? ? ? 85 C0 74 07 32 DB E9 ? ? ? ? E8 ? ? ? ? 8B F8 85 FF");
    
    if (((uintptr_t)_ReturnAddress() == (uintptr_t)retaddr1)) // 这个返回地址只能是ncm写入的地址
    {
        std::wstring wFileName = FindFileName(lpFileName);
        if (FileInfo[wFileName].ptr != nullptr)
        {
            std::wstring filename = lpFileName;
            filename += L".mp3"; // 懒得弄重命名了

            FILE* file = _wfopen(filename.c_str(), L"wb");
            fwrite(FileInfo[wFileName].ptr, 1, FileInfo[wFileName].size, file);
            fclose(file);
            free(FileInfo[wFileName].ptr);
            FileInfo[wFileName].ptr = nullptr; FileInfo[wFileName].size = 0;
        }
    }
    if ((uintptr_t)_ReturnAddress() == (uintptr_t)retaddr)
    {
        std::wstring m_sFileName = std::wstring(lpFileName);
        // 转换小写，网易云你打不败我的
        std::transform(m_sFileName.begin(), m_sFileName.end(), m_sFileName.begin(),
            [](unsigned char c) { return std::tolower(c); });

        // 可能会有一些我们不需要的垃圾数据，确保以.mp3结尾
        if (m_sFileName.find(L"netease\\cloudmusic\\temp") != std::wstring::npos && m_sFileName.find(L".mp3") != std::wstring::npos)
        {
            std::wstring wFileName = FindFileName(lpFileName);

            FILE* file = _wfopen(lpFileName, L"rb");
            fseek(file, 0, SEEK_END);
            FileInfo[wFileName].size = ftell(file);
            fseek(file, 0, SEEK_SET);

            FileInfo[wFileName].ptr = malloc(FileInfo[wFileName].size);
            fread(FileInfo[wFileName].ptr, 1, FileInfo[wFileName].size, file);
            fclose(file);
        }
    }
    // 返回原函数
    return ((decltype(hk_CreateFileW)*)(o_CreateFileW))(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        VersionHijack::Initialize();
        MH_Initialize();
        MH_CreateHook(CreateFileW, hk_CreateFileW, &o_CreateFileW);
        MH_EnableHook(MH_ALL_HOOKS);
    }
    return TRUE;
}

