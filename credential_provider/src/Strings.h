#pragma once

#include <windows.h>

namespace NfcAuth
{
    inline constexpr wchar_t kTileLabel[] = L"NFC認証";
    inline constexpr wchar_t kPasswordFieldLabel[] = L"パスワード";
    inline constexpr wchar_t kSubmitFieldLabel[] = L"送信";
    inline constexpr wchar_t kStatusPrompt[] = L"カードをかざしてください";
    inline constexpr wchar_t kStatusAuthenticated[] = L"カード認証済み: パスワードを入力してください";
    inline constexpr wchar_t kStatusUnavailable[] = L"NFCサービスに接続できません";
    inline constexpr wchar_t kStatusChecking[] = L"NFC認証を確認しています。もう一度送信してください";
    inline constexpr wchar_t kStatusPasswordRequired[] = L"パスワードを入力してください";
    inline constexpr wchar_t kStatusAuthenticationFailed[] = L"NFC認証に失敗しました。カードをかざしてください";
    inline constexpr wchar_t kStatusUserMissing[] = L"認証するWindowsユーザーを確認できません";
    inline constexpr wchar_t kStatusUserAmbiguous[] = L"Windowsユーザーを特定できません。対象ユーザーを1人にしてから再試行してください";
    inline constexpr wchar_t kStatusSerializationFailed[] = L"Windows認証情報を作成できません";

    enum FieldId : DWORD
    {
        FieldStatus = 0,
        FieldPassword = 1,
        FieldSubmit = 2,
        FieldCount = 3
    };
}
