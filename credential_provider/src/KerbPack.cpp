#include "KerbPack.h"

#include <ntsecapi.h>
#include <objbase.h>
#include <limits>

namespace NfcAuth
{
    namespace
    {
        bool GetStringBytes(const std::wstring& value, SIZE_T* bytes) noexcept
        {
            if (!bytes || value.find(L'\0') != std::wstring::npos)
            {
                return false;
            }

            const SIZE_T chars = value.size();
            if (chars > (static_cast<SIZE_T>(USHRT_MAX) - sizeof(WCHAR)) / sizeof(WCHAR))
            {
                return false;
            }

            *bytes = (chars + 1) * sizeof(WCHAR);
            return true;
        }

        void SetOffsetString(UNICODE_STRING* target, BYTE* base, SIZE_T offset,
                             const std::wstring& value, SIZE_T bytes) noexcept
        {
            target->Length = static_cast<USHORT>(bytes - sizeof(WCHAR));
            target->MaximumLength = static_cast<USHORT>(bytes);
            target->Buffer = reinterpret_cast<PWSTR>(static_cast<ULONG_PTR>(offset));
            CopyMemory(base + offset, value.c_str(), bytes);
        }
    }

    HRESULT PackKerbLogon(const std::wstring& domain,
                          const std::wstring& user,
                          const std::wstring& password,
                          KerbScenario scenario,
                          BYTE** buffer,
                          ULONG* bufferSize) noexcept
    {
        if (buffer) *buffer = nullptr;
        if (bufferSize) *bufferSize = 0;
        if (!buffer || !bufferSize) return E_POINTER;
        if (scenario != KerbScenario::Logon && scenario != KerbScenario::Unlock)
            return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);

        SIZE_T domainBytes = 0;
        SIZE_T userBytes = 0;
        SIZE_T passwordBytes = 0;
        if (!GetStringBytes(domain, &domainBytes) ||
            !GetStringBytes(user, &userBytes) ||
            !GetStringBytes(password, &passwordBytes))
        {
            return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
        }

        constexpr SIZE_T headerBytes = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);
        if (domainBytes > (std::numeric_limits<SIZE_T>::max)() - headerBytes ||
            userBytes > (std::numeric_limits<SIZE_T>::max)() - headerBytes - domainBytes ||
            passwordBytes > (std::numeric_limits<SIZE_T>::max)() - headerBytes - domainBytes - userBytes)
        {
            return HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
        }

        const SIZE_T totalBytes = headerBytes + domainBytes + userBytes + passwordBytes;
        if (totalBytes > (std::numeric_limits<ULONG>::max)())
        {
            return HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
        }

        BYTE* data = static_cast<BYTE*>(CoTaskMemAlloc(totalBytes));
        if (!data)
        {
            return E_OUTOFMEMORY;
        }
        ZeroMemory(data, totalBytes);

        auto* packed = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(data);
        packed->Logon.MessageType = scenario == KerbScenario::Unlock
            ? KerbWorkstationUnlockLogon
            : KerbInteractiveLogon;

        SIZE_T offset = headerBytes;
        SetOffsetString(&packed->Logon.LogonDomainName, data, offset, domain, domainBytes);
        offset += domainBytes;
        SetOffsetString(&packed->Logon.UserName, data, offset, user, userBytes);
        offset += userBytes;
        SetOffsetString(&packed->Logon.Password, data, offset, password, passwordBytes);

        *buffer = data;
        *bufferSize = static_cast<ULONG>(totalBytes);
        return S_OK;
    }

    void SecureZeroPassword(std::wstring& password) noexcept
    {
        if (!password.empty())
        {
            SecureZeroMemory(&password[0], password.size() * sizeof(WCHAR));
        }
    }

    void SecureFreeKerbBuffer(BYTE* buffer, ULONG bufferSize) noexcept
    {
        if (buffer)
        {
            SecureZeroMemory(buffer, bufferSize);
            CoTaskMemFree(buffer);
        }
    }
}
