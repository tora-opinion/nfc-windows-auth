#include "../src/KerbPack.h"

#include <ntsecapi.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <string>
#include <vector>

using namespace NfcAuth;

namespace
{
    size_t OffsetOf(PWSTR pointer)
    {
        return static_cast<size_t>(reinterpret_cast<ULONG_PTR>(pointer));
    }

    std::wstring ReadString(const BYTE* buffer, ULONG bufferSize, const UNICODE_STRING& value)
    {
        const size_t offset = OffsetOf(value.Buffer);
        assert(offset >= sizeof(KERB_INTERACTIVE_UNLOCK_LOGON));
        assert(offset + value.MaximumLength <= bufferSize);
        assert(value.MaximumLength >= sizeof(WCHAR));
        assert(value.Length <= value.MaximumLength - sizeof(WCHAR));
        assert(buffer[offset + value.Length] == 0);
        return std::wstring(reinterpret_cast<const WCHAR*>(buffer + offset),
                            value.Length / sizeof(WCHAR));
    }

    void TestOffsetsAndScenarios()
    {
        BYTE* buffer = nullptr;
        ULONG size = 0;
        assert(PackKerbLogon(L"DESKTOP", L"suger", L"typed-secret",
                             KerbScenario::Logon, &buffer, &size) == S_OK);
        auto* packed = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(buffer);
        assert(packed->Logon.MessageType == KerbInteractiveLogon);
        const size_t domainOffset = OffsetOf(packed->Logon.LogonDomainName.Buffer);
        const size_t userOffset = OffsetOf(packed->Logon.UserName.Buffer);
        const size_t passwordOffset = OffsetOf(packed->Logon.Password.Buffer);
        assert(domainOffset == sizeof(KERB_INTERACTIVE_UNLOCK_LOGON));
        assert(userOffset == domainOffset + packed->Logon.LogonDomainName.MaximumLength);
        assert(passwordOffset == userOffset + packed->Logon.UserName.MaximumLength);
        assert(ReadString(buffer, size, packed->Logon.LogonDomainName) == L"DESKTOP");
        assert(ReadString(buffer, size, packed->Logon.UserName) == L"suger");
        assert(ReadString(buffer, size, packed->Logon.Password) == L"typed-secret");
        SecureFreeKerbBuffer(buffer, size);

        buffer = nullptr;
        size = 0;
        assert(PackKerbLogon(L".", L"suger", L"pw", KerbScenario::Unlock,
                             &buffer, &size) == S_OK);
        packed = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(buffer);
        assert(packed->Logon.MessageType == KerbWorkstationUnlockLogon);
        SecureFreeKerbBuffer(buffer, size);
    }

    void TestUnicodeAndEmptyInputs()
    {
        BYTE* buffer = nullptr;
        ULONG size = 0;
        const std::wstring domain = L"会社";
        const std::wstring user = L"利用者";
        const std::wstring password = L"秘密🙂";
        assert(PackKerbLogon(domain, user, password, KerbScenario::Logon,
                             &buffer, &size) == S_OK);
        auto* packed = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(buffer);
        assert(packed->Logon.LogonDomainName.Length == domain.size() * sizeof(WCHAR));
        assert(packed->Logon.UserName.Length == user.size() * sizeof(WCHAR));
        assert(packed->Logon.Password.Length == password.size() * sizeof(WCHAR));
        assert(ReadString(buffer, size, packed->Logon.LogonDomainName) == domain);
        assert(ReadString(buffer, size, packed->Logon.UserName) == user);
        assert(ReadString(buffer, size, packed->Logon.Password) == password);
        SecureFreeKerbBuffer(buffer, size);

        buffer = nullptr;
        size = 0;
        assert(PackKerbLogon(L"", L"", L"", KerbScenario::Logon, &buffer, &size) == S_OK);
        packed = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(buffer);
        assert(packed->Logon.LogonDomainName.Length == 0);
        assert(packed->Logon.UserName.Length == 0);
        assert(packed->Logon.Password.Length == 0);
        assert(packed->Logon.LogonDomainName.MaximumLength == sizeof(WCHAR));
        assert(packed->Logon.UserName.MaximumLength == sizeof(WCHAR));
        assert(packed->Logon.Password.MaximumLength == sizeof(WCHAR));
        assert(ReadString(buffer, size, packed->Logon.Password).empty());
        SecureFreeKerbBuffer(buffer, size);
    }

    void TestLengthLimitsAndEmbeddedNul()
    {
        BYTE* buffer = nullptr;
        ULONG size = 0;
        const std::wstring longestAllowed(32766, L'd');
        assert(PackKerbLogon(longestAllowed, L"u", L"p", KerbScenario::Logon,
                             &buffer, &size) == S_OK);
        auto* packed = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(buffer);
        assert(packed->Logon.LogonDomainName.Length == 65532);
        assert(packed->Logon.LogonDomainName.MaximumLength == 65534);
        SecureFreeKerbBuffer(buffer, size);

        const std::wstring tooLong(32767, L'd');
        assert(PackKerbLogon(tooLong, L"u", L"p", KerbScenario::Logon,
                             &buffer, &size) == HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER));
        assert(buffer == nullptr && size == 0);

        const std::wstring embeddedNul(L"a\0b", 3);
        assert(PackKerbLogon(L"d", L"u", embeddedNul, KerbScenario::Logon,
                             &buffer, &size) == HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER));
        assert(buffer == nullptr && size == 0);
    }

    void TestPasswordZeroing()
    {
        std::wstring password = L"password-that-must-be-erased";
        const size_t size = password.size();
        SecureZeroPassword(password);
        assert(password.size() == size);
        for (wchar_t c : password) assert(c == 0);
    }
}

int main()
{
    TestOffsetsAndScenarios();
    TestUnicodeAndEmptyInputs();
    TestLengthLimitsAndEmbeddedNul();
    TestPasswordZeroing();
    return 0;
}
