#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>
#include "AES.h"
#include "json.hpp"

const unsigned char HeaderFlag[] = "\x43\x54\x45\x4E\x46\x44\x41\x4D\x01\x70";
std::vector<unsigned char> Core_key = { 0x68,0x7A,0x48,0x52,0x41,0x6D,0x73,0x6F,0x35,0x6B,0x49,0x6E,0x62,0x61,0x78,0x57 };
std::vector<unsigned char> Meta_key = { 0x23,0x31,0x34,0x6C,0x6A,0x6B,0x5F,0x21,0x5C,0x5D,0x26,0x30,0x55,0x3C,0x27,0x28 };

static std::string base64_encode(const std::string& in) {

    std::string out;

    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

static std::string base64_decode(const std::string& in) {

    std::string out;

    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

void decrypt(std::string file_input_path,std::string file_output_path)
{
    FILE* file = fopen(file_input_path.c_str(), "rb");
    char buffer[sizeof(HeaderFlag) - 1];
    fread(&buffer, 1, sizeof(HeaderFlag) - 1, file);
    if (memcmp(buffer, HeaderFlag, sizeof(HeaderFlag) - 1) != 0)
    {
        return;
    }
    DWORD key_length;
    fread(&key_length, 4, 1, file);

    unsigned char* key = (unsigned char*)malloc(key_length);
    fread(key, 1, key_length, file);

    std::vector<unsigned char> key_data;

    for (int i = 0; i < key_length; i++)
    {
        key[i] ^= 0x64;
        key_data.push_back(key[i]); //pack data to vector
    }

    AES aes(AESKeyLength::AES_128);

    std::vector<unsigned char> decrypted = aes.DecryptECB(key_data, Core_key);
    for (int i = 0xd; i > 0x0; i--) //remove footer
    {
        decrypted.pop_back();
    }
    for (int i = 0; i < 17; i++) //remove header
    {
        decrypted.erase(decrypted.begin());
    }
    key_data.clear();
    key_data = decrypted;
    decrypted.clear();

    key_length = key_data.size();

    unsigned char key_box[256] = { 0 };
    for (int i = 0; i < 256; i++)
    {
        key_box[i] = i;
    }

    int j = 0, k = 0;
    for (int i = 0; i < 256; i++)
    {
        unsigned char tmp = key_box[i];
        j = (j + tmp + key_data[k]) % 256;
        key_box[i] = key_box[j];
        key_box[j] = tmp;
        if (++k >= key_length) k = 0;
    }

    DWORD meta_length;
    fread(&meta_length, 4, 1, file);

    unsigned char* meta_data = (unsigned char*)malloc(meta_length);
    fread(meta_data, 1, meta_length, file);

    std::vector<unsigned char> metadata;
    for (int i = 0; i < meta_length; i++)
    {
        meta_data[i] ^= 0x63;
        metadata.push_back(meta_data[i]);
    }

    std::string encoded_data = std::string((const char*)((uintptr_t)metadata.data() + 22));

    std::string decoded = base64_decode(encoded_data);

    metadata.clear();

    for (int i = 0; i < decoded.size(); i++)
    {
        metadata.push_back(decoded[i]);
    }

    auto decrypted_meta = aes.DecryptECB(metadata, Meta_key);

    std::string meta_data_str = std::string((const char*)decrypted_meta.data() + 6);

    meta_data_str.resize(meta_data_str.size() - 13);

    //nlohmann::json meta_json(meta_data_str);

    DWORD crc32;
    fread(&crc32, 4, 1, file);

    fseek(file, 5, SEEK_CUR);

    DWORD image_size;
    fread(&image_size, 4, 1, file);

    void* image_data = malloc(image_size);
    fread(image_data, 1, image_size, file);

    unsigned char* chunk = (unsigned char*)malloc(0x8000);
    FILE* output = fopen(file_output_path.c_str(), "wb");
    while (1)
    {
        if (fread(chunk, 1, 0x8000, file) != 0x8000) // actual read size != 0x8000 , mb its file end,so we finish it
        {
            break;
        }
        for (int i = 0; i < 0x8001; i++)
        {
            DWORD j = i & 0xff;
            chunk[i - 1] ^= key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff];
        }
        fwrite(chunk, 1, 0x8000, output);
    }
    fclose(file);
    fclose(output);
}

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
    ret.resize(ret.size() - 4); //we dont need file format .mp3 .ncm
    return ret;
}


int main(int argc,char** argv)
{
    std::string file_path;
    
    if (!argv[1])
    {
        file_path = "G:\\CloudMusic\\The Pitcher - Collide.ncm";
    }
    else
    {
        file_path = argv[1];
    }
    decrypt(file_path,"c:\\out.mp3");
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
