#include "../src/StoredCredential.h"

#include <windows.h>
#include <wincrypt.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <string>
#include <vector>

using namespace NfcAuth;

namespace
{
    // Must stay byte-identical to _CREDENTIAL_ENTROPY in src/nfc_store.py.
    const char kEntropy[] = "NfcAuth.Credential.v1";

    std::wstring TempFilePath()
    {
        wchar_t directory[MAX_PATH + 1] = {};
        const DWORD length = GetTempPathW(MAX_PATH, directory);
        assert(length > 0 && length <= MAX_PATH);
        wchar_t path[MAX_PATH + 1] = {};
        assert(GetTempFileNameW(directory, L"nfc", 0, path) != 0);
        return std::wstring(path);
    }

    void WriteBytes(const std::wstring& path, const void* data, DWORD size)
    {
        HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        assert(file != INVALID_HANDLE_VALUE);
        DWORD written = 0;
        assert(WriteFile(file, data, size, &written, nullptr) != FALSE);
        assert(written == size);
        CloseHandle(file);
    }

    // Produces exactly what nfc_store.save_credential writes.
    void WriteRecord(const std::wstring& path, const std::string& record)
    {
        std::string plaintext = record;
        DATA_BLOB input{ static_cast<DWORD>(plaintext.size()),
                         reinterpret_cast<BYTE*>(plaintext.data()) };
        DATA_BLOB entropy{ static_cast<DWORD>(sizeof(kEntropy) - 1),
                           reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy)) };
        DATA_BLOB output{};
        assert(CryptProtectData(&input, nullptr, &entropy, nullptr, nullptr,
                                CRYPTPROTECT_LOCAL_MACHINE, &output) != FALSE);
        WriteBytes(path, output.pbData, output.cbData);
        LocalFree(output.pbData);
    }

    void TestReadsTheRecordWrittenByTheAdminTool()
    {
        const std::wstring path = TempFilePath();
        WriteRecord(path, "MicrosoftAccount\\someone@example.com\npa ss:word");

        std::wstring user;
        std::wstring password;
        assert(LoadStoredCredentialFromPath(path.c_str(), &user, &password));
        assert(user == L"MicrosoftAccount\\someone@example.com");
        assert(password == L"pa ss:word");
        DeleteFileW(path.c_str());
    }

    void TestSplitsOnlyOnTheFirstNewline()
    {
        const std::wstring path = TempFilePath();
        WriteRecord(path, ".\\local\nfirst\nsecond");

        std::wstring user;
        std::wstring password;
        assert(LoadStoredCredentialFromPath(path.c_str(), &user, &password));
        assert(user == L".\\local");
        assert(password == L"first\nsecond");
        DeleteFileW(path.c_str());
    }

    void TestKeepsNonAsciiPasswordsIntact()
    {
        const std::wstring path = TempFilePath();
        // UTF-8 for ".\\local" and the password "パスワードxyz".
        WriteRecord(path, ".\\local\n\xE3\x83\x91\xE3\x82\xB9\xE3\x83\xAF"
                          "\xE3\x83\xBC\xE3\x83\x89xyz");

        std::wstring user;
        std::wstring password;
        assert(LoadStoredCredentialFromPath(path.c_str(), &user, &password));
        assert(user == L".\\local");
        assert(password == L"\u30D1\u30B9\u30EF\u30FC\u30C9xyz");
        DeleteFileW(path.c_str());
    }

    void TestRejectsUnusableBlobs()
    {
        std::wstring user = L"stale";
        std::wstring password = L"stale";

        // A path that does not exist.
        assert(!LoadStoredCredentialFromPath(L"C:\\nfc-auth-no-such-file.dpapi",
                                             &user, &password));
        assert(user.empty() && password.empty());

        // Ciphertext that DPAPI cannot unprotect.
        const std::wstring corrupt = TempFilePath();
        const char garbage[] = "not a dpapi blob";
        WriteBytes(corrupt, garbage, static_cast<DWORD>(sizeof(garbage) - 1));
        assert(!LoadStoredCredentialFromPath(corrupt.c_str(), &user, &password));
        DeleteFileW(corrupt.c_str());

        // Well-formed ciphertext whose plaintext is not "<user>\n<password>".
        const std::wstring noSeparator = TempFilePath();
        WriteRecord(noSeparator, "onlyauser");
        assert(!LoadStoredCredentialFromPath(noSeparator.c_str(), &user, &password));
        DeleteFileW(noSeparator.c_str());

        const std::wstring emptyUser = TempFilePath();
        WriteRecord(emptyUser, "\nsecret");
        assert(!LoadStoredCredentialFromPath(emptyUser.c_str(), &user, &password));
        DeleteFileW(emptyUser.c_str());

        const std::wstring emptyPassword = TempFilePath();
        WriteRecord(emptyPassword, ".\\local\n");
        assert(!LoadStoredCredentialFromPath(emptyPassword.c_str(), &user, &password));
        DeleteFileW(emptyPassword.c_str());

        // An empty file.
        const std::wstring empty = TempFilePath();
        WriteBytes(empty, "", 0);
        assert(!LoadStoredCredentialFromPath(empty.c_str(), &user, &password));
        DeleteFileW(empty.c_str());
    }

    void TestRejectsNullArguments()
    {
        std::wstring user;
        std::wstring password;
        assert(!LoadStoredCredentialFromPath(nullptr, &user, &password));
        assert(!LoadStoredCredentialFromPath(L"C:\\x", nullptr, &password));
        assert(!LoadStoredCredentialFromPath(L"C:\\x", &user, nullptr));
    }
}

int main()
{
    TestReadsTheRecordWrittenByTheAdminTool();
    TestSplitsOnlyOnTheFirstNewline();
    TestKeepsNonAsciiPasswordsIntact();
    TestRejectsUnusableBlobs();
    TestRejectsNullArguments();
    return 0;
}
