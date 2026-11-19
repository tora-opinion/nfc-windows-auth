#pragma once

#include <windows.h>
#include <string>

namespace NfcAuth
{
    enum class KerbScenario
    {
        Logon,
        Unlock
    };

    // The caller owns the returned CoTaskMemAlloc buffer and must free it.
    // UNICODE_STRING.Buffer members contain byte offsets from the buffer start.
    HRESULT PackKerbLogon(
        const std::wstring& domain,
        const std::wstring& user,
        const std::wstring& password,
        KerbScenario scenario,
        BYTE** buffer,
        ULONG* bufferSize) noexcept;

    void SecureZeroPassword(std::wstring& password) noexcept;
    void SecureFreeKerbBuffer(BYTE* buffer, ULONG bufferSize) noexcept;
}
