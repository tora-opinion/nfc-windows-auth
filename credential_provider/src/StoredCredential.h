#pragma once

#include <string>

namespace NfcAuth
{
    // Loads the optional auto sign-in credential written by the admin tool to
    // %ProgramData%\NfcAuth\credential.dpapi, whose DACL grants only SYSTEM and
    // the local Administrators group.
    //
    // Returns false whenever no usable credential is configured. That is the
    // normal, safe case: the provider then stays in its typed-password mode and
    // the tap only acts as the first factor.
    bool LoadStoredCredential(std::wstring* user, std::wstring* password) noexcept;

    // Same decryption and parsing against an explicit path, so the on-disk
    // contract with the Python admin tool can be covered by a test.
    bool LoadStoredCredentialFromPath(const wchar_t* path, std::wstring* user,
                                      std::wstring* password) noexcept;
}
