#include "pch.h"
#include "security.h"

namespace AntiCrack {

std::string         SecurityEngine::s_hwid;
uint8_t             SecurityEngine::s_textBaseline[32] = {};
bool                SecurityEngine::s_initialized       = false;
volatile void*      SecurityEngine::s_trapPointer1      = nullptr;
volatile void*      SecurityEngine::s_trapPointer2      = nullptr;
std::atomic<bool>   SecurityEngine::s_retaliated        { false };

// SHA-256

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

void SHA256_Compute(const uint8_t* data, size_t len, uint8_t digest[32]) {
    uint32_t h[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };

    const size_t msgLen = len;
    size_t zeroPad = (msgLen % 64 < 56) ?
                     (55 - msgLen % 64) :
                     (119 - msgLen % 64);
    const size_t totalLen = msgLen + 1 + zeroPad + 8;

    std::vector<uint8_t> msg(totalLen, 0u);
    if (len > 0) memcpy(msg.data(), data, len);
    msg[msgLen] = 0x80u;
    const uint64_t bitLen = static_cast<uint64_t>(msgLen) * 8u;
    for (int i = 0; i < 8; ++i) {
        msg[totalLen - 8u + static_cast<size_t>(i)] =
            static_cast<uint8_t>(bitLen >> (56u - static_cast<unsigned>(i) * 8u));
    }

    for (size_t offset = 0; offset < totalLen; offset += 64u) {
        uint32_t w[64];

        for (int i = 0; i < 16; ++i) {
            const size_t b = offset + static_cast<size_t>(i) * 4u;
            w[i] = (static_cast<uint32_t>(msg[b + 0]) << 24u)
                 | (static_cast<uint32_t>(msg[b + 1]) << 16u)
                 | (static_cast<uint32_t>(msg[b + 2]) <<  8u)
                 |  static_cast<uint32_t>(msg[b + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = _rotr(w[i - 15], 7)
                              ^ _rotr(w[i - 15], 18)
                              ^ (w[i - 15] >> 3u);
            const uint32_t s1 = _rotr(w[i - 2], 17)
                              ^ _rotr(w[i - 2], 19)
                              ^ (w[i - 2] >> 10u);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hv = h[7];

        for (int i = 0; i < 64; ++i) {
            const uint32_t S1   = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
            const uint32_t ch   = (e & f) ^ (~e & g);
            const uint32_t t1   = hv + S1 + ch + SHA256_K[i] + w[i];
            const uint32_t S0   = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
            const uint32_t maj  = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2   = S0 + maj;

            hv = g;  g = f;  f = e;  e = d + t1;
            d  = c;  c = b;  b = a;  a = t1 + t2;
        }

        h[0] += a;  h[1] += b;  h[2] += c;  h[3] += d;
        h[4] += e;  h[5] += f;  h[6] += g;  h[7] += hv;
    }

    for (int i = 0; i < 8; ++i) {
        digest[static_cast<size_t>(i) * 4u + 0u] = static_cast<uint8_t>(h[i] >> 24u);
        digest[static_cast<size_t>(i) * 4u + 1u] = static_cast<uint8_t>(h[i] >> 16u);
        digest[static_cast<size_t>(i) * 4u + 2u] = static_cast<uint8_t>(h[i] >>  8u);
        digest[static_cast<size_t>(i) * 4u + 3u] = static_cast<uint8_t>(h[i]);
    }
}

std::string SHA256_ToHex(const uint8_t digest[32]) {
    static const char kHexChars[] = "0123456789abcdef";
    std::string result;
    result.reserve(64u);
    for (int i = 0; i < 32; ++i) {
        result += kHexChars[(digest[i] >> 4u) & 0x0Fu];
        result += kHexChars[ digest[i]         & 0x0Fu];
    }
    return result;
}

// Hardware ID

std::string SecurityEngine::GatherCPUID() {
    int cpuInfo[4] = { 0, 0, 0, 0 };
    char vendor[13] = {};
    char brand[49]  = {};

    __cpuid(cpuInfo, 0);
    // CPUID stores the vendor string in EBX, EDX, -- ECX
    memcpy(vendor + 0, &cpuInfo[1], 4u);
    memcpy(vendor + 4, &cpuInfo[3], 4u);
    memcpy(vendor + 8, &cpuInfo[2], 4u);
    vendor[12] = '\0';

    __cpuid(cpuInfo, static_cast<int>(0x80000000));
    if (static_cast<unsigned int>(cpuInfo[0]) >= 0x80000004u) {
        __cpuid(cpuInfo, static_cast<int>(0x80000002));
        memcpy(brand +  0, cpuInfo, 16u);
        __cpuid(cpuInfo, static_cast<int>(0x80000003));
        memcpy(brand + 16, cpuInfo, 16u);
        __cpuid(cpuInfo, static_cast<int>(0x80000004));
        memcpy(brand + 32, cpuInfo, 16u);
        brand[48] = '\0';
    } else {
        strncpy_s(brand, 49, "CPU_BRAND_UNAVAILABLE", _TRUNCATE);
    }

    __cpuid(cpuInfo, 1);
    const DWORD featECX = static_cast<DWORD>(cpuInfo[2]);
    const DWORD featEDX = static_cast<DWORD>(cpuInfo[3]);

    char result[320];
    sprintf_s(result, "%s|%s|%08X|%08X", vendor, brand, featECX, featEDX);
    return std::string(result);
}

std::string SecurityEngine::GatherMotherboardSerial() {
    std::string result = "MB_SERIAL_UNAVAILABLE";

    const HRESULT hrInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool    comOurs = (hrInit == S_OK || hrInit == S_FALSE);

    IWbemLocator*  pLoc = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, reinterpret_cast<void**>(&pLoc)
    );
    if (FAILED(hr)) { if (comOurs) CoUninitialize(); return result; }

    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pSvc
    );
    if (FAILED(hr)) {
        pLoc->Release();
        if (comOurs) CoUninitialize();
        return result;
    }

    CoSetProxyBlanket(
        pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE
    );

    IEnumWbemClassObject* pEnum = nullptr;
    hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT SerialNumber FROM Win32_BaseBoard"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnum
    );

    if (SUCCEEDED(hr) && pEnum) {
        IWbemClassObject* pObj = nullptr;
        ULONG returned = 0u;
        if (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == WBEM_S_NO_ERROR
            && returned > 0u)
        {
            VARIANT vtSerial;
            VariantInit(&vtSerial);
            hr = pObj->Get(L"SerialNumber", 0, &vtSerial, nullptr, nullptr);
            if (SUCCEEDED(hr) && vtSerial.vt == VT_BSTR && vtSerial.bstrVal) {
                const int needed = WideCharToMultiByte(
                    CP_UTF8, 0, vtSerial.bstrVal, -1,
                    nullptr, 0, nullptr, nullptr
                );
                if (needed > 1) {
                    result.resize(static_cast<size_t>(needed - 1));
                    WideCharToMultiByte(
                        CP_UTF8, 0, vtSerial.bstrVal, -1,
                        &result[0], needed, nullptr, nullptr
                    );
                }
            }
            VariantClear(&vtSerial);
            pObj->Release();
        }
        pEnum->Release();
    }

    pSvc->Release();
    pLoc->Release();
    if (comOurs) CoUninitialize();
    return result;
}

std::string SecurityEngine::GatherDriveSerial() {
    std::string result = "DRIVE_SERIAL_UNAVAILABLE";

    HANDLE hDevice = CreateFileA(
        "\\\\.\\PhysicalDrive0",
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (hDevice != INVALID_HANDLE_VALUE) {
        STORAGE_PROPERTY_QUERY spq = {};
        spq.PropertyId = StorageDeviceProperty;
        spq.QueryType  = PropertyStandardQuery;

        const DWORD bufSize = 4096u;
        std::vector<uint8_t> outBuf(bufSize, 0u);
        DWORD bytesReturned = 0u;

        if (DeviceIoControl(
            hDevice,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &spq,     sizeof(spq),
            outBuf.data(), bufSize,
            &bytesReturned, nullptr
        ) && bytesReturned > sizeof(STORAGE_DEVICE_DESCRIPTOR))
        {
            const STORAGE_DEVICE_DESCRIPTOR* desc =
                reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(outBuf.data());

            if (desc->SerialNumberOffset != 0u &&
                desc->SerialNumberOffset < bytesReturned)
            {
                const char* rawSerial = reinterpret_cast<const char*>(
                    outBuf.data() + desc->SerialNumberOffset
                );
                result = rawSerial;
                while (!result.empty() && result.front() == ' ')
                    result.erase(result.begin());
                while (!result.empty() && (result.back() == ' ' || result.back() == '\0'))
                    result.pop_back();
            }
        }
        CloseHandle(hDevice);
    } else {
        // Fall back to the C: volume serial.
        DWORD volSerial = 0u;
        if (GetVolumeInformationA(
            "C:\\", nullptr, 0u, &volSerial,
            nullptr, nullptr, nullptr, 0u))
        {
            char buf[16];
            sprintf_s(buf, "VOL_%08X", volSerial);
            result = buf;
        }
    }

    return result;
}

std::string SecurityEngine::GetHWID() {
    if (!s_hwid.empty()) return s_hwid;

    const std::string cpuStr   = GatherCPUID();
    const std::string mbStr    = GatherMotherboardSerial();
    const std::string driveStr = GatherDriveSerial();

    const std::string combined = cpuStr + "<<||>>" + mbStr + "<<||>>" + driveStr;

    uint8_t digest[32];
    SHA256_Compute(
        reinterpret_cast<const uint8_t*>(combined.data()),
        combined.size(), digest
    );

    s_hwid = SHA256_ToHex(digest);
    return s_hwid;
}

// .text section integrity

bool SecurityEngine::ComputeTextSectionBaseline() {
    const HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod) return false;

    const BYTE* base = reinterpret_cast<const BYTE*>(hMod);
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    const IMAGE_NT_HEADERS64* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        base + dos->e_lfanew
    );
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    const WORD numSections = nt->FileHeader.NumberOfSections;

    for (WORD i = 0u; i < numSections; ++i) {
        if (memcmp(sections[i].Name, ".text\0\0\0", 8u) == 0) {
            const BYTE*  textBase = base + sections[i].VirtualAddress;
            const DWORD  textSize = sections[i].Misc.VirtualSize;
            SHA256_Compute(textBase, textSize, s_textBaseline);
            return true;
        }
    }
    return false;
}

bool SecurityEngine::VerifyTextSection() {
    const HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod) return true;  // Cannot verify — treat as clean.

    const BYTE* base = reinterpret_cast<const BYTE*>(hMod);
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const IMAGE_NT_HEADERS64* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        base + dos->e_lfanew
    );
    const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    const WORD numSections = nt->FileHeader.NumberOfSections;

    for (WORD i = 0u; i < numSections; ++i) {
        if (memcmp(sections[i].Name, ".text\0\0\0", 8u) == 0) {
            const BYTE* textBase = base + sections[i].VirtualAddress;
            const DWORD textSize = sections[i].Misc.VirtualSize;
            uint8_t currentHash[32];
            SHA256_Compute(textBase, textSize, currentHash);
            return (memcmp(currentHash, s_textBaseline, 32u) == 0);
        }
    }
    return true;
}

// Debugger and tool checks

bool SecurityEngine::CheckPEB() {
    // On Windows x64, GS:[0x60] points to the PEB.
    const BYTE* peb = reinterpret_cast<const BYTE*>(__readgsqword(0x60));
    if (!peb) return false;

    if (peb[2] != 0u) {
        return true;
    }

    // Mask the three heap debug flags set at process startup.
    const DWORD ntGlobalFlag = *reinterpret_cast<const DWORD*>(peb + 0xBCu);
    if (ntGlobalFlag & 0x70u) {
        return true;
    }

    const PVOID processHeap = *reinterpret_cast<const PVOID*>(peb + 0x30u);
    if (processHeap) {
        // ForceFlags offset in the x64 heap layout.
        const DWORD forceFlags = *reinterpret_cast<const DWORD*>(
            reinterpret_cast<const BYTE*>(processHeap) + 0x74u
        );
        if (forceFlags != 0u) {
            return true;
        }
    }

    return false;
}

bool SecurityEngine::CheckDebugRegisters() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        return false;
    }

    if (ctx.Dr0 != 0u || ctx.Dr1 != 0u ||
        ctx.Dr2 != 0u || ctx.Dr3 != 0u) {
        return true;
    }

    // Mask the local-enable bits for DR0–DR3.
    if (ctx.Dr7 & 0x55u) {
        return true;
    }

    return false;
}

bool SecurityEngine::CheckTiming() {
    static LARGE_INTEGER s_freq    = {};
    static LARGE_INTEGER s_lastQPC = {};

    if (s_freq.QuadPart == 0LL) {
        QueryPerformanceFrequency(&s_freq);
        QueryPerformanceCounter(&s_lastQPC);
        return false;
    }

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);

    const double elapsedMs =
        static_cast<double>(now.QuadPart - s_lastQPC.QuadPart)
        / static_cast<double>(s_freq.QuadPart) * 1000.0;

    s_lastQPC = now;

    // Allow up to four times the 1,200 ms polling interval.
    if (elapsedMs > 4800.0) {
        return true;
    }
    return false;
}

#include <tlhelp32.h>

bool SecurityEngine::CheckBlacklistedProcesses(std::string& outDetails) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0u);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32 = {};
        pe32.dwSize = sizeof(pe32);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                char narrowName[MAX_PATH] = {};
                size_t convertedChars = 0;
                wcstombs_s(&convertedChars, narrowName, sizeof(narrowName), pe32.szExeFile, _TRUNCATE);

                std::string name(narrowName);
                for (auto& c : name) c = static_cast<char>(tolower(c));

                const auto tool1 = XSTR("ida.exe").decrypt();
                const auto tool2 = XSTR("ida64.exe").decrypt();
                const auto tool3 = XSTR("idat64.exe").decrypt();
                const auto tool4 = XSTR("x64dbg.exe").decrypt();
                const auto tool5 = XSTR("x32dbg.exe").decrypt();
                const auto tool6 = XSTR("cheatengine").decrypt();
                const auto tool7 = XSTR("scylla.exe").decrypt();
                const auto tool8 = XSTR("ollydbg.exe").decrypt();

                if (name == tool1.c_str() || name == tool2.c_str() || name == tool3.c_str() ||
                    name == tool4.c_str() || name == tool5.c_str() || name == tool7.c_str() ||
                    name == tool8.c_str() || name.find(tool6.c_str()) != std::string::npos) 
                {
                    CloseHandle(hSnapshot);
                    outDetails = "process '" + name + "'";
                    return true;
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    const auto win1 = XSTR("ida").decrypt();
    const auto win2 = XSTR("x64dbg").decrypt();
    const auto win3 = XSTR("cheat engine").decrypt();
    const auto win4 = XSTR("scylla").decrypt();

    if (FindWindowA(nullptr, "x64dbg") != nullptr) {
        outDetails = "window: 'x64dbg'";
        return true;
    }
    if (FindWindowA(nullptr, "Cheat Engine") != nullptr) {
        outDetails = "window: 'Cheat Engine'";
        return true;
    }
    if (FindWindowA(nullptr, "Scylla") != nullptr) {
        outDetails = "window: 'Scylla'";
        return true;
    }

    HWND hwnd = GetForegroundWindow();
    if (hwnd != nullptr) {
        char title[256] = {};
        if (GetWindowTextA(hwnd, title, 256) > 0) {
            std::string wtitle(title);
            std::string wtitle_lower = wtitle;
            for (auto& c : wtitle_lower) c = static_cast<char>(tolower(c));

            if (wtitle_lower.find(win1.c_str()) != std::string::npos ||
                wtitle_lower.find(win2.c_str()) != std::string::npos ||
                wtitle_lower.find(win3.c_str()) != std::string::npos ||
                wtitle_lower.find(win4.c_str()) != std::string::npos) 
            {
                outDetails = "active window title: '" + wtitle + "'";
                return true;
            }
        }
    }

    return false;
}

// Persistent registry marker

// Changing the salt invalidates existing registry markers.
static const uint64_t STIGMA_SALT = 0xDEADBEEFCAFEBABEULL;

static constexpr auto S_REG_PATH = XSTR(
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\DriverOperations"
);

static constexpr auto S_REG_VALUE_NAME = XSTR("SessionFilter");

std::string SecurityEngine::ComputeStigmaValue(const std::string& hwid) {
    std::string input;
    input.reserve(hwid.size() + 8u);
    input = hwid;
    for (int i = 0; i < 8; ++i) {
        input += static_cast<char>((STIGMA_SALT >> (static_cast<unsigned>(i) * 8u)) & 0xFFu);
    }

    uint8_t digest[32];
    SHA256_Compute(
        reinterpret_cast<const uint8_t*>(input.data()),
        input.size(), digest
    );
    return SHA256_ToHex(digest);
}

bool SecurityEngine::CheckStigma(const std::string& hwid) {
    const auto decPath  = S_REG_PATH.decrypt();
    const auto decValue = S_REG_VALUE_NAME.decrypt();

    HKEY hKey = nullptr;
    LONG res = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        decPath.c_str(),
        0, KEY_READ, &hKey
    );
    if (res != ERROR_SUCCESS) return false;

    char   valueBuf[128] = {};
    DWORD  dataSize      = static_cast<DWORD>(sizeof(valueBuf));
    DWORD  dataType      = REG_NONE;

    res = RegQueryValueExA(
        hKey, decValue.c_str(), nullptr,
        &dataType, reinterpret_cast<BYTE*>(valueBuf), &dataSize
    );
    RegCloseKey(hKey);

    if (res != ERROR_SUCCESS || dataType != REG_SZ) return false;

    const std::string actual = valueBuf;
    const std::string expected = ComputeStigmaValue(hwid);

    return (actual.find(expected) == 0);
}

void SecurityEngine::PlantStigma(const std::string& hwid, const std::string& reason) {
    const auto decPath  = S_REG_PATH.decrypt();
    const auto decValue = S_REG_VALUE_NAME.decrypt();

    HKEY  hKey = nullptr;
    DWORD disposition = 0u;

    LONG res = RegCreateKeyExA(
        HKEY_CURRENT_USER,
        decPath.c_str(),
        0, nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        nullptr,
        &hKey,
        &disposition
    );
    if (res != ERROR_SUCCESS) return;

    // Store the marker as HASH|REASON.
    const std::string stigmaVal = ComputeStigmaValue(hwid) + "|" + reason;
    RegSetValueExA(
        hKey,
        decValue.c_str(),
        0, REG_SZ,
        reinterpret_cast<const BYTE*>(stigmaVal.c_str()),
        static_cast<DWORD>(stigmaVal.size() + 1u) 
    );
    RegCloseKey(hKey);
}

std::string SecurityEngine::GetStigmaReason() {
    const auto decPath  = S_REG_PATH.decrypt();
    const auto decValue = S_REG_VALUE_NAME.decrypt();

    HKEY hKey = nullptr;
    LONG res = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        decPath.c_str(),
        0, KEY_READ, &hKey
    );
    if (res != ERROR_SUCCESS) return "UNKNOWN_VIOLATION";

    char   valueBuf[256] = {};
    DWORD  dataSize      = static_cast<DWORD>(sizeof(valueBuf));
    DWORD  dataType      = REG_NONE;

    res = RegQueryValueExA(
        hKey, decValue.c_str(), nullptr,
        &dataType, reinterpret_cast<BYTE*>(valueBuf), &dataSize
    );
    RegCloseKey(hKey);

    if (res != ERROR_SUCCESS || dataType != REG_SZ) return "UNKNOWN_VIOLATION";

    std::string content(valueBuf);
    size_t pipePos = content.find('|');
    if (pipePos != std::string::npos) {
        return content.substr(pipePos + 1);
    }
    return "UNKNOWN_VIOLATION";
}

std::string SecurityEngine::GetFriendlyReason(const std::string& rawReason) {
    if (rawReason.find("HACKING_TOOL_DETECTED") != std::string::npos) {
        size_t start = rawReason.find('(');
        size_t end = rawReason.find(')');
        if (start != std::string::npos && end != std::string::npos && end > start + 1) {
            std::string details = rawReason.substr(start + 1, end - start - 1);
            return
        }
        return
    }

    if (rawReason == "PEB_DEBUGGER_DETECTED") {
        return "PEB Debugger Flag Active";
    }
    if (rawReason == "HARDWARE_BREAKPOINT_DETECTED") {
        return "Hardware Breakpoint  Debug Registers";
    }
    if (rawReason == "TIMING_ANOMALY_DETECTED") {
        return "";
    }
    if (rawReason == "CODE_SECTION_PATCH_DETECTED") {
        return "text segment integrity mismatch";
    }
    if (rawReason == "LICENSE_INVALID") {
        return "การตรวจสอบไลเซนส์ไม่ผ่าน";
    }
    if (rawReason == "MANUAL_VIOLATION_REPORT") {
        return "การรายงานความปลอดภัยด้วยตนเอง (Manual Security Report)";
    }

    return "ความปลอดภัยล้มเหลว: " + rawReason;
}

static constexpr auto S_API_HOST     = XSTR("async.uiavgcgccggv.workers.dev");
static constexpr auto S_API_PATH     = XSTR("/v2/sys/telemetry/sync/logs");
static constexpr auto S_API_TOKEN    = XSTR("c7e1b5f2a9d84e3c9b6a1f8e2d7c5b4a");
static constexpr auto S_USER_AGENT   = XSTR("Microsoft-CryptoAPI/10.0");

void SecurityEngine::SendViolationReport(
    const std::string& hwid,
    const std::string& pcName,  
    const std::string& reason)
{
    const auto decHost   = S_API_HOST.decrypt();
    const auto decPath   = S_API_PATH.decrypt();
    const auto decToken  = S_API_TOKEN.decrypt();
    const auto decUA     = S_USER_AGENT.decrypt();

    std::string hexReason;
    hexReason.reserve(reason.length() * 2);
    for (char ch : reason) {
        unsigned char val = static_cast<unsigned char>(ch ^ 0x5Au);
        char hex[3];
        sprintf_s(hex, "%02x", val);
        hexReason += hex;
    }

    SYSTEMTIME st = {};
    GetSystemTime(&st);
    char tsStr[32];
    sprintf_s(tsStr, "%04u-%02u-%02uT%02u:%02u:%02uZ",
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond);

    char jsonBuf[2048];
    sprintf_s(jsonBuf,
        R"({"hwid":"%s","pc":"%s","reason":"%s","ts":"%s"})",
        hwid.c_str(), pcName.c_str(), hexReason.c_str(), tsStr
    );

    char headersBuf[512];
    sprintf_s(headersBuf,
        "Content-Type: application/json\r\n"
        "X-Windows-Internal-Token: %s\r\n",
        decToken.c_str()
    );

    HINTERNET hInet = InternetOpenA(
        decUA.c_str(),
        INTERNET_OPEN_TYPE_PRECONFIG,
        nullptr, nullptr, 0u
    );
    if (!hInet) return;

    HINTERNET hConn = InternetConnectA(
        hInet,
        decHost.c_str(),
        INTERNET_DEFAULT_HTTPS_PORT,
        nullptr, nullptr,
        INTERNET_SERVICE_HTTP, 0u, 0u
    );
    if (!hConn) {
        InternetCloseHandle(hInet);
        return;
    }

    const DWORD reqFlags =
        INTERNET_FLAG_SECURE           |
        INTERNET_FLAG_RELOAD           |
        INTERNET_FLAG_NO_CACHE_WRITE;

    HINTERNET hReq = HttpOpenRequestA(
        hConn, "POST", decPath.c_str(),
        "HTTP/1.1", nullptr, nullptr,
        reqFlags, 0u
    );
    if (!hReq) {
        InternetCloseHandle(hConn);
        InternetCloseHandle(hInet);
        return;
    }

    HttpSendRequestA(
        hReq,
        headersBuf, static_cast<DWORD>(strlen(headersBuf)),
        jsonBuf,    static_cast<DWORD>(strlen(jsonBuf))
    );

    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    InternetCloseHandle(hInet);
}

void SecurityEngine::ExecuteRetaliation(const char* reason) {
    bool expected = false;
    if (!s_retaliated.compare_exchange_strong(
            expected, true,
            std::memory_order_acq_rel, std::memory_order_acquire))
    {
        return;
    }

    PlantStigma(s_hwid, reason ? reason : "UNKNOWN_VIOLATION");

    char pcName[256] = {};
    DWORD nameLen = static_cast<DWORD>(sizeof(pcName));
    GetComputerNameA(pcName, &nameLen);

    std::string hwidCopy   = s_hwid;
    std::string pcCopy     = pcName;
    std::string reasonCopy = (reason ? reason : "UNKNOWN_VIOLATION");

    std::thread([hwidCopy, pcCopy, reasonCopy]() {

        SecurityEngine::SendViolationReport(hwidCopy, pcCopy, reasonCopy);

        SecurityEngine::s_trapPointer1 = reinterpret_cast<void*>(0xDEADC0DE00000001ULL);
        SecurityEngine::s_trapPointer2 = reinterpret_cast<void*>(0xBAADF00D0BADF00DULL);

        Sleep(10000UL);

        TerminateProcess(GetCurrentProcess(), 0u);
        volatile int* const badPtr = nullptr;
        *badPtr = 0xDEAD;
    }).detach();
}

// Watchdog

void SecurityEngine::WatchdogLoop() {
    std::this_thread::sleep_for(std::chrono::milliseconds(800));

    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1200));

        if (s_retaliated.load(std::memory_order_acquire)) {
            continue;
        }

        const char* violationReason = nullptr;

        if (CheckPEB()) {
            violationReason = "PEB_DEBUGGER_DETECTED";
        }
        else if (CheckDebugRegisters()) {
            violationReason = "HARDWARE_BREAKPOINT_DETECTED";
        }
        else if (CheckTiming()) {
            violationReason = "TIMING_ANOMALY_DETECTED";
        }
        else if (!VerifyTextSection()) {
            violationReason = "CODE_SECTION_PATCH_DETECTED";
        }
        else {
            static std::string s_dynamicReason;
            std::string detectedDetails;
            if (CheckBlacklistedProcesses(detectedDetails)) {
                s_dynamicReason = "HACKING_TOOL_DETECTED (" + detectedDetails + ")";
                violationReason = s_dynamicReason.c_str();
            }
        }

        if (violationReason) {
            ExecuteRetaliation(violationReason);
        }
    }
}

void SecurityEngine::StartWatchdogThread() {
    std::thread t([]() { WatchdogLoop(); });
    t.detach();
}

// Public API

bool SecurityEngine::Initialize() {
    if (s_initialized) return true;

    s_hwid = GetHWID();

    if (CheckStigma(s_hwid)) {
        std::string rawReason = GetStigmaReason();
        std::string friendlyMsg = GetFriendlyReason(rawReason);
        
        std::string msgBoxText = friendlyMsg;
        
        MessageBoxA(
            nullptr,
            msgBoxText.c_str(),
            "Banned",
            MB_OK | MB_ICONERROR | MB_SYSTEMMODAL
        );
        ExitProcess(0u);
        return false;
    }

    ComputeTextSectionBaseline();

    StartWatchdogThread();

    s_initialized = true;
    return true;
}

void SecurityEngine::ReportViolation(const char* reason) {
    ExecuteRetaliation(reason ? reason : "MANUAL_VIOLATION_REPORT");
}

} // namespace AntiCrack
