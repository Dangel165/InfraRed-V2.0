#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <iomanip>
#include <cstdio>   // _wfopen_s 사용을 위해 추가
#include <openssl/md5.h> // 반드시 OpenSSL 설치 필요

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

// === 시그니처 및 해시 DB ===
static std::vector<std::string> signatures = {
    "malware", "virus", "trojan", "badstuff"
};

static std::set<std::string> bad_hashes = {
    "098f6bcd4621d373cade4e832627b4f6", // md5: "test"
    // 실제 해시 값을 여기에 추가(소문자)
};

// === 파일 전체 읽기 ===
// wchar_t* (Wide Character, 유니코드) 경로를 받습니다.
std::string read_all(const wchar_t* filepath) {
    FILE* file;
    // _wfopen_s를 사용하여 Wide Character 경로를 기반으로 파일을 안전하게 엽니다.
    // L"rb"는 Wide Character 문자열로 "rb"를 의미합니다.
    if (_wfopen_s(&file, filepath, L"rb") != 0 || !file) {
        return ""; // 파일 열기 실패 시 빈 문자열 반환
    }
    
    std::string content;
    
    // 파일 크기 계산
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // 크기만큼 메모리 할당 및 읽기
    if (size > 0) {
        content.resize(size);
        fread(&content[0], 1, size, file);
    }
    
    fclose(file);
    return content;
}

// === 시그니처 검사 ===
bool contains_signature(const std::string& content) {
    for (const auto& sig : signatures) {
        if (content.find(sig) != std::string::npos)
            return true;
    }
    return false;
}

// === MD5 해시 계산 ===
std::string calc_md5(const std::string& content) {
    unsigned char md[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)content.data(), content.size(), md);
    std::ostringstream oss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)md[i];
    return oss.str();
}

// === 외부 호출 함수 ===
extern "C" {
    // 파일 검사: 0=정상, 1=시그니처, 2=해시, -1=파일오류
    // 시그니처를 const wchar_t*로 변경
    EXPORT int scan_file(const wchar_t* filepath) { 
        // read_all 함수도 wchar_t*를 받도록 수정되었습니다.
        std::string content = read_all(filepath);
        if (content.empty()) return -1; // 파일 열기 실패

        if (contains_signature(content))
            return 1;
        std::string file_hash = calc_md5(content);
        if (bad_hashes.count(file_hash))
            return 2;

        return 0;
    }
}