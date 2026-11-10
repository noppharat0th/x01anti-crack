#pragma once

#include "pch.h"

namespace AntiCrack {

static constexpr uint8_t CT_KEY_SEED = 0xB3u;

template<size_t N>
struct EncryptedString {
    uint8_t encrypted[N]{};

    constexpr explicit EncryptedString(const char (&plaintext)[N]) noexcept {
        for (size_t i = 0; i < N; ++i) {
            uint8_t k = static_cast<uint8_t>(
                CT_KEY_SEED ^ static_cast<uint8_t>(i * 7u) ^ static_cast<uint8_t>(i >> 3u)
            );
            encrypted[i] = static_cast<uint8_t>(plaintext[i]) ^ k;
        }
    }

    struct Decrypted {
        char buf[N]{};

        explicit Decrypted(const EncryptedString<N>& enc) noexcept {
            for (size_t i = 0; i < N; ++i) {
                uint8_t k = static_cast<uint8_t>(
                    CT_KEY_SEED ^ static_cast<uint8_t>(i * 7u) ^ static_cast<uint8_t>(i >> 3u)
                );
                buf[i] = static_cast<char>(enc.encrypted[i] ^ k);
            }
        }

        // Use volatile writes so the compiler preserves the buffer wipe.
        ~Decrypted() noexcept {
            volatile char* p = buf;
            for (size_t i = 0; i < N; ++i) p[i] = '\0';
        }

        Decrypted(const Decrypted&)            = delete;
        Decrypted& operator=(const Decrypted&) = delete;

        Decrypted(Decrypted&& other) noexcept {
            memcpy(buf, other.buf, N);
        }
        Decrypted& operator=(Decrypted&& other) noexcept {
            if (this != &other) {
                memcpy(buf, other.buf, N);
            }
            return *this;
        }

        [[nodiscard]] const char* c_str() const noexcept { return buf; }
        operator const char*()             const noexcept { return buf; }
    };

    [[nodiscard]] Decrypted decrypt() const noexcept {
        return Decrypted(*this);
    }
};

// Include the terminating null byte in the encoded literal.
#define XSTR(s) (::AntiCrack::EncryptedString<sizeof(s)>(s))

void SHA256_Compute(const uint8_t* data, size_t len, uint8_t digest[32]);

std::string SHA256_ToHex(const uint8_t digest[32]);

class SecurityEngine {
public:
    // Call at startup to check the local ban marker and start monitoring.
    static bool Initialize();

    // Returns the cached 64-character lowercase hex HWID.
    [[nodiscard]] static std::string GetHWID();

    // Records a violation and schedules process termination.
    static void ReportViolation(const char* reason);

    static bool ComputeTextSectionBaseline();

    [[nodiscard]] static bool VerifyTextSection();

    static void SendViolationReport(
        const std::string& hwid,
        const std::string& pcName,
        const std::string& reason
    );

    static std::atomic<bool> s_retaliated;

private:
    static std::string      s_hwid;
    static uint8_t          s_textBaseline[32];
    static bool             s_initialized;
    static volatile void*   s_trapPointer1;
    static volatile void*   s_trapPointer2;

    [[nodiscard]] static std::string GatherCPUID();
    [[nodiscard]] static std::string GatherMotherboardSerial();
    [[nodiscard]] static std::string GatherDriveSerial();

    [[nodiscard]] static std::string ComputeStigmaValue(const std::string& hwid);
    [[nodiscard]] static bool  CheckStigma(const std::string& hwid);
    static void PlantStigma(const std::string& hwid, const std::string& reason);
    [[nodiscard]] static std::string GetStigmaReason();
    [[nodiscard]] static std::string GetFriendlyReason(const std::string& rawReason);

    [[nodiscard]] static bool CheckPEB();
    [[nodiscard]] static bool CheckDebugRegisters();
    [[nodiscard]] static bool CheckTiming();
    [[nodiscard]] static bool CheckBlacklistedProcesses(std::string& outDetails);

    static void ExecuteRetaliation(const char* reason);

    static void StartWatchdogThread();
    static void WatchdogLoop();
};

} // namespace AntiCrack
