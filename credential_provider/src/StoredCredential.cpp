#include "StoredCredential.h"

#include "KerbPack.h"

#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>

#include <vector>

namespace NfcAuth
{
    namespace
    {
        // Not a secret. The entropy only scopes the blob to this feature so an
        // unrelated machine-scope DPAPI blob cannot be dropped in its place.
        const char kEntropy[] = "NfcAuth.Credential.v1";

        // The plaintext is a short UTF-8 record, so anything larger is corrupt.
        constexpr LONGLONG kMaxBlobBytes = 64 * 1024;

        bool CredentialPath(std::wstring* path) noexcept
        {
            PWSTR programData = nullptr;
            if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DEFAULT,
                                            nullptr, &programData)) || !programData)
                return false;
            bool ok = true;
            try
            {
                path->assign(programData);
                path->append(L"\\NfcAuth\\credential.dpapi");
            }
            catch (...)
            {
                ok = false;
            }
            CoTaskMemFree(programData);
            return ok;
        }

        bool ReadBlob(const wchar_t* path, std::vector<BYTE>* blob) noexcept
        {
            HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE) return false;

            LARGE_INTEGER size{};
            if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
                size.QuadPart > kMaxBlobBytes)
            {
                CloseHandle(file);
                return false;
            }

            bool ok = false;
            try
            {
                blob->resize(static_cast<size_t>(size.QuadPart));
                DWORD read = 0;
                ok = ReadFile(file, blob->data(), static_cast<DWORD>(blob->size()),
                              &read, nullptr) != FALSE &&
                     read == static_cast<DWORD>(blob->size());
            }
            catch (...)
            {
                ok = false;
            }
            CloseHandle(file);
            return ok;
        }

        bool Utf8ToWide(const char* data, int bytes, std::wstring* text) noexcept
        {
            if (bytes <= 0)
            {
                text->clear();
                return true;
            }
            const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                                   data, bytes, nullptr, 0);
            if (needed <= 0) return false;
            try
            {
                text->resize(static_cast<size_t>(needed));
            }
            catch (...)
            {
                return false;
            }
            return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data, bytes,
                                       &(*text)[0], needed) == needed;
        }

        // The record is "<qualified user>\n<password>". A newline cannot appear
        // in a Windows account name, so one split is unambiguous and no parser
        // has to run over attacker-reachable text.
        bool ParseRecord(const BYTE* plaintext, DWORD bytes,
                         std::wstring* user, std::wstring* password) noexcept
        {
            if (!plaintext || bytes == 0 || bytes > static_cast<DWORD>(kMaxBlobBytes))
                return false;
            const char* text = reinterpret_cast<const char*>(plaintext);
            DWORD split = 0;
            while (split < bytes && text[split] != '\n') ++split;
            if (split == 0 || split == bytes) return false;

            if (!Utf8ToWide(text, static_cast<int>(split), user)) return false;
            if (!Utf8ToWide(text + split + 1, static_cast<int>(bytes - split - 1), password))
                return false;
            return !user->empty() && !password->empty();
        }
    }

    bool LoadStoredCredential(std::wstring* user, std::wstring* password) noexcept
    {
        std::wstring path;
        if (!CredentialPath(&path))
        {
            if (user) user->clear();
            if (password) password->clear();
            return false;
        }
        return LoadStoredCredentialFromPath(path.c_str(), user, password);
    }

    bool LoadStoredCredentialFromPath(const wchar_t* path, std::wstring* user,
                                      std::wstring* password) noexcept
    {
        if (!path || !user || !password) return false;
        user->clear();
        password->clear();

        std::vector<BYTE> blob;
        if (!ReadBlob(path, &blob)) return false;

        DATA_BLOB input{ static_cast<DWORD>(blob.size()), blob.data() };
        DATA_BLOB entropy{ static_cast<DWORD>(sizeof(kEntropy) - 1),
                           reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy)) };
        DATA_BLOB output{};
        if (!CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr, 0, &output))
        {
            SecureZeroMemory(blob.data(), blob.size());
            return false;
        }

        const bool parsed = ParseRecord(output.pbData, output.cbData, user, password);

        SecureZeroMemory(output.pbData, output.cbData);
        LocalFree(output.pbData);
        SecureZeroMemory(blob.data(), blob.size());

        if (!parsed)
        {
            user->clear();
            SecureZeroPassword(*password);
            password->clear();
        }
        return parsed;
    }
}
