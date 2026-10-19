#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#ifdef NFC_AUTH_TESTING
#include <windows.h>
#endif

namespace NfcAuth
{
    enum class PipeResultKind
    {
        ServiceUnavailable,
        NoTap,
        Tap,
        Consumed,
        Error
    };

    struct PipeResult
    {
        PipeResultKind kind = PipeResultKind::Error;
        std::wstring user;
        std::uint32_t ttlMs = 0;
        std::string nonce;
        std::wstring error;
    };

    class PipeClient final
    {
    public:
        static PipeResult QueryStatus() noexcept;
        static PipeResult Consume(std::string_view nonce) noexcept;
    };

    class IAuthService
    {
    public:
        virtual ~IAuthService() = default;
        virtual PipeResult QueryStatus() noexcept = 0;
        virtual PipeResult Consume(std::string_view nonce) noexcept = 0;
    };

    class PipeAuthService final : public IAuthService
    {
    public:
        PipeResult QueryStatus() noexcept override { return PipeClient::QueryStatus(); }
        PipeResult Consume(std::string_view nonce) noexcept override
        {
            return PipeClient::Consume(nonce);
        }
    };

    IAuthService& DefaultAuthService() noexcept;

    // Shared by production and parser tests so the nonce is validated without normalization.
    bool BuildConsumeRequest(std::string_view nonce, std::string* request) noexcept;

    // Exposed for parser-only tests; these functions do no pipe I/O.
    PipeResult ParseStatusResponse(std::string_view json) noexcept;
    PipeResult ParseConsumeResponse(std::string_view json) noexcept;

#ifdef NFC_AUTH_TESTING
    namespace Testing
    {
        using ServerIdentityProvider = bool (*)(HANDLE pipe, BYTE* userSid,
                                                DWORD* userSidBytes) noexcept;
        PipeResult Exchange(const wchar_t* pipeName, std::string_view request,
                            bool consume, ServerIdentityProvider identityProvider) noexcept;
    }
#endif
}
