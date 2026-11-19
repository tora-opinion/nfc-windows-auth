#pragma once

#include <windows.h>

namespace NfcAuth
{
    // Shown as the tile's headline. "Suica" names the Express Card the reader
    // talks to; the artwork deliberately avoids JR East's logo and mascot.
    inline constexpr wchar_t kTileLabel[] = L"iPhone (Suica) でサインイン";
    inline constexpr wchar_t kPasswordFieldLabel[] = L"パスワード";
    inline constexpr wchar_t kSubmitFieldLabel[] = L"送信";
    inline constexpr wchar_t kStatusPrompt[] = L"iPhone をリーダーにかざしてください";
    inline constexpr wchar_t kStatusAuthenticated[] = L"iPhone を確認しました。パスワードを入力してください";
    inline constexpr wchar_t kStatusUnavailable[] = L"NFC サービスに接続できません";
    inline constexpr wchar_t kStatusChecking[] = L"NFC 認証を確認しています。もう一度送信してください";
    inline constexpr wchar_t kStatusPasswordRequired[] = L"パスワードを入力してください";
    inline constexpr wchar_t kStatusAuthenticationFailed[] = L"NFC 認証に失敗しました。もう一度かざしてください";
    inline constexpr wchar_t kStatusUserMissing[] = L"認証する Windows ユーザーを確認できません";
    inline constexpr wchar_t kStatusUserAmbiguous[] = L"Windows ユーザーを特定できません。対象ユーザーを 1 人にしてから再試行してください";
    inline constexpr wchar_t kStatusSerializationFailed[] = L"Windows 認証情報を作成できません";

    enum FieldId : DWORD
    {
        FieldTileImage = 0,
        FieldLabel = 1,
        FieldStatus = 2,
        FieldPassword = 3,
        FieldSubmit = 4,
        FieldCount = 5
    };
}
