#include "PipeClient.h"

#include <windows.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <utility>
#include <vector>

namespace NfcAuth
{
    namespace
    {
        constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\NfcAuthTap";
        constexpr size_t kMaxMessageBytes = 4096;
        constexpr DWORD kConnectTimeoutMs = 500;
        constexpr DWORD kWriteTimeoutMs = 500;
        constexpr DWORD kReadTimeoutMs = 1000;

        using ServerIdentityProvider = bool (*)(HANDLE pipe, BYTE* userSid,
                                                DWORD* userSidBytes) noexcept;

        class ScopedHandle final
        {
        public:
            explicit ScopedHandle(HANDLE handle = nullptr) noexcept : handle_(handle) {}
            ~ScopedHandle() { if (handle_ && handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_); }
            ScopedHandle(const ScopedHandle&) = delete;
            ScopedHandle& operator=(const ScopedHandle&) = delete;
            HANDLE get() const noexcept { return handle_; }

        private:
            HANDLE handle_;
        };

        struct ParsedObject
        {
            bool hasVersion = false;
            std::int64_t version = 0;
            bool hasOk = false;
            bool ok = false;
            bool hasTap = false;
            bool tap = false;
            bool hasUser = false;
            bool userIsNull = false;
            std::wstring user;
            bool hasTtl = false;
            std::int64_t ttl = 0;
            bool hasNonce = false;
            std::wstring nonce;
            bool hasError = false;
            std::wstring error;
        };

        class JsonReader final
        {
        public:
            explicit JsonReader(std::string_view input) noexcept : input_(input) {}

            bool Parse(ParsedObject* object) noexcept
            {
                if (!object || input_.size() > kMaxMessageBytes)
                {
                    return false;
                }
                try
                {
                    SkipWhitespace();
                    if (!Take('{')) return false;
                    SkipWhitespace();
                    if (Take('}'))
                    {
                        SkipWhitespace();
                        return position_ == input_.size();
                    }

                    for (unsigned int count = 0; count < 8; ++count)
                    {
                        std::wstring key;
                        if (!ReadString(&key)) return false;
                        SkipWhitespace();
                        if (!Take(':')) return false;
                        SkipWhitespace();
                        if (!ReadProperty(key, object)) return false;
                        SkipWhitespace();
                        if (Take('}'))
                        {
                            SkipWhitespace();
                            return position_ == input_.size();
                        }
                        if (!Take(',')) return false;
                        SkipWhitespace();
                    }
                }
                catch (...)
                {
                    return false;
                }
                return false;
            }

        private:
            static bool IsWhitespace(char c) noexcept
            {
                return c == ' ' || c == '\t' || c == '\r' || c == '\n';
            }

            void SkipWhitespace() noexcept
            {
                while (position_ < input_.size() && IsWhitespace(input_[position_])) ++position_;
            }

            bool Take(char expected) noexcept
            {
                if (position_ >= input_.size() || input_[position_] != expected) return false;
                ++position_;
                return true;
            }

            bool ReadString(std::wstring* output)
            {
                if (!output || !Take('"')) return false;
                std::string utf8;
                while (position_ < input_.size())
                {
                    const unsigned char c = static_cast<unsigned char>(input_[position_++]);
                    if (c == '"')
                    {
                        if (utf8.empty())
                        {
                            output->clear();
                            return true;
                        }
                        const int required = MultiByteToWideChar(
                            CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                            static_cast<int>(utf8.size()), nullptr, 0);
                        if (required <= 0) return false;
                        output->resize(static_cast<size_t>(required));
                        return MultiByteToWideChar(
                            CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                            static_cast<int>(utf8.size()), &(*output)[0], required) == required;
                    }
                    if (c < 0x20) return false;
                    if (c != '\\')
                    {
                        utf8.push_back(static_cast<char>(c));
                        continue;
                    }

                    if (position_ >= input_.size()) return false;
                    const char escape = input_[position_++];
                    switch (escape)
                    {
                    case '"': utf8.push_back('"'); break;
                    case '\\': utf8.push_back('\\'); break;
                    case '/': utf8.push_back('/'); break;
                    case 'b': return false;
                    case 'f': return false;
                    case 'n': return false;
                    case 'r': return false;
                    case 't': return false;
                    case 'u':
                    {
                        unsigned int codePoint = 0;
                        if (!ReadHexWord(&codePoint)) return false;
                        if (codePoint >= 0xD800 && codePoint <= 0xDBFF)
                        {
                            if (position_ + 2 > input_.size() || input_[position_] != '\\' || input_[position_ + 1] != 'u')
                                return false;
                            position_ += 2;
                            unsigned int low = 0;
                            if (!ReadHexWord(&low) || low < 0xDC00 || low > 0xDFFF) return false;
                            codePoint = 0x10000 + ((codePoint - 0xD800) << 10) + (low - 0xDC00);
                        }
                        else if (codePoint >= 0xDC00 && codePoint <= 0xDFFF)
                        {
                            return false;
                        }
                        AppendUtf8(codePoint, &utf8);
                        break;
                    }
                    default:
                        return false;
                    }
                }
                return false;
            }

            bool ReadHexWord(unsigned int* value) noexcept
            {
                if (!value || position_ + 4 > input_.size()) return false;
                unsigned int result = 0;
                for (unsigned int i = 0; i < 4; ++i)
                {
                    const char c = input_[position_++];
                    unsigned int digit = 0;
                    if (c >= '0' && c <= '9') digit = static_cast<unsigned int>(c - '0');
                    else if (c >= 'a' && c <= 'f') digit = static_cast<unsigned int>(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') digit = static_cast<unsigned int>(c - 'A' + 10);
                    else return false;
                    result = (result << 4) | digit;
                }
                *value = result;
                return true;
            }

            static void AppendUtf8(unsigned int codePoint, std::string* output)
            {
                if (codePoint <= 0x7F) output->push_back(static_cast<char>(codePoint));
                else if (codePoint <= 0x7FF)
                {
                    output->push_back(static_cast<char>(0xC0 | (codePoint >> 6)));
                    output->push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
                }
                else if (codePoint <= 0xFFFF)
                {
                    output->push_back(static_cast<char>(0xE0 | (codePoint >> 12)));
                    output->push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
                    output->push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
                }
                else
                {
                    output->push_back(static_cast<char>(0xF0 | (codePoint >> 18)));
                    output->push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F)));
                    output->push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
                    output->push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
                }
            }

            bool ReadInteger(std::int64_t* value) noexcept
            {
                if (!value) return false;
                const size_t start = position_;
                bool negative = false;
                if (position_ < input_.size() && input_[position_] == '-')
                {
                    negative = true;
                    ++position_;
                }
                if (position_ >= input_.size() || input_[position_] < '0' || input_[position_] > '9') return false;
                if (input_[position_] == '0' && position_ + 1 < input_.size() &&
                    input_[position_ + 1] >= '0' && input_[position_ + 1] <= '9') return false;
                std::uint64_t magnitude = 0;
                while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9')
                {
                    const unsigned int digit = static_cast<unsigned int>(input_[position_++] - '0');
                    if (magnitude > (static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) +
                                      (negative ? 1ULL : 0ULL) - digit) / 10ULL) return false;
                    magnitude = magnitude * 10ULL + digit;
                }
                if (position_ == start) return false;
                if (position_ < input_.size() &&
                    (input_[position_] == '.' || input_[position_] == 'e' || input_[position_] == 'E')) return false;
                if (negative)
                {
                    if (magnitude == static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) + 1ULL)
                        *value = (std::numeric_limits<std::int64_t>::min)();
                    else *value = -static_cast<std::int64_t>(magnitude);
                }
                else *value = static_cast<std::int64_t>(magnitude);
                return true;
            }

            bool ReadLiteral(const char* text) noexcept
            {
                const size_t length = strlen(text);
                if (input_.size() - position_ < length || input_.substr(position_, length) != text) return false;
                position_ += length;
                return true;
            }

            bool ReadProperty(const std::wstring& key, ParsedObject* object)
            {
                if (key == L"v")
                {
                    if (object->hasVersion || !ReadInteger(&object->version)) return false;
                    object->hasVersion = true;
                    return true;
                }
                if (key == L"ok")
                {
                    if (object->hasOk) return false;
                    if (ReadLiteral("true")) object->ok = true;
                    else if (ReadLiteral("false")) object->ok = false;
                    else return false;
                    object->hasOk = true;
                    return true;
                }
                if (key == L"tap")
                {
                    if (object->hasTap) return false;
                    if (ReadLiteral("true")) object->tap = true;
                    else if (ReadLiteral("false")) object->tap = false;
                    else return false;
                    object->hasTap = true;
                    return true;
                }
                if (key == L"user")
                {
                    if (object->hasUser) return false;
                    if (ReadLiteral("null")) object->userIsNull = true;
                    else if (!ReadString(&object->user)) return false;
                    object->hasUser = true;
                    return true;
                }
                if (key == L"ttl_ms")
                {
                    if (object->hasTtl || !ReadInteger(&object->ttl)) return false;
                    object->hasTtl = true;
                    return true;
                }
                if (key == L"nonce")
                {
                    if (object->hasNonce || !ReadString(&object->nonce)) return false;
                    object->hasNonce = true;
                    return true;
                }
                if (key == L"error")
                {
                    if (object->hasError || !ReadString(&object->error)) return false;
                    object->hasError = true;
                    return true;
                }
                return false;
            }

            std::string_view input_;
            size_t position_ = 0;
        };

        bool IsNonce(const std::wstring& nonce) noexcept
        {
            if (nonce.size() != 32) return false;
            for (wchar_t c : nonce)
            {
                if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ||
                      (c >= L'A' && c <= L'F'))) return false;
            }
            return true;
        }

        bool IsNonce(std::string_view nonce) noexcept
        {
            if (nonce.size() != 32) return false;
            for (char c : nonce)
            {
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                      (c >= 'A' && c <= 'F'))) return false;
            }
            return true;
        }

        bool HasControlCharacter(const std::wstring& value) noexcept
        {
            for (wchar_t c : value)
            {
                if (c < 0x20 || (c >= 0x7F && c <= 0x9F)) return true;
            }
            return false;
        }

        bool IsAllowedError(const std::wstring& error) noexcept
        {
            return error == L"bad_request" || error == L"no_tap" ||
                   error == L"expired" || error == L"bad_nonce";
        }

        PipeResult ParseResponse(std::string_view json, bool consume)
        {
            PipeResult result;
            if (json.size() > kMaxMessageBytes)
            {
                result.error = L"oversize_response";
                return result;
            }

            ParsedObject object;
            JsonReader reader(json);
            if (!reader.Parse(&object) || !object.hasVersion || object.version != 1 || !object.hasOk)
            {
                result.error = L"bad_response";
                return result;
            }

            if (!object.ok)
            {
                const bool onlyError = object.hasError && !object.hasTap && !object.hasUser &&
                                       !object.hasTtl && !object.hasNonce;
                if (!onlyError || !IsAllowedError(object.error) ||
                    (!consume && object.error != L"bad_request"))
                {
                    result.error = L"bad_response";
                    return result;
                }
                result.error = object.error;
                result.kind = (object.error == L"no_tap" || object.error == L"expired")
                    ? PipeResultKind::NoTap : PipeResultKind::Error;
                return result;
            }

            if (object.hasError)
            {
                result.error = L"bad_response";
                return result;
            }
            if (consume)
            {
                if (object.hasTap || object.hasUser || object.hasTtl || object.hasNonce)
                {
                    result.error = L"bad_response";
                    return result;
                }
                result.kind = PipeResultKind::Consumed;
                return result;
            }

            if (!object.hasTap)
            {
                result.error = L"bad_response";
                return result;
            }
            if (!object.tap)
            {
                if (object.hasUser || object.hasTtl || object.hasNonce)
                {
                    result.error = L"bad_response";
                    return result;
                }
                result.kind = PipeResultKind::NoTap;
                return result;
            }

            if (!object.hasUser || !object.hasTtl || !object.hasNonce ||
                object.ttl <= 0 || object.ttl > 120000 || !IsNonce(object.nonce) ||
                (!object.userIsNull && (object.user.empty() || HasControlCharacter(object.user))))
            {
                result.error = L"bad_response";
                return result;
            }
            result.kind = PipeResultKind::Tap;
            if (!object.userIsNull) result.user = std::move(object.user);
            result.ttlMs = static_cast<std::uint32_t>(object.ttl);
            result.nonce.reserve(object.nonce.size());
            for (wchar_t c : object.nonce) result.nonce.push_back(static_cast<char>(c));
            return result;
        }

        bool WaitOverlapped(HANDLE pipe, OVERLAPPED* overlapped, DWORD timeoutMs,
                            DWORD* transferred, DWORD* failure) noexcept
        {
            const DWORD wait = WaitForSingleObject(overlapped->hEvent, timeoutMs);
            if (wait == WAIT_TIMEOUT)
            {
                CancelIoEx(pipe, overlapped);
                GetOverlappedResult(pipe, overlapped, transferred, TRUE);
                if (failure) *failure = ERROR_SEM_TIMEOUT;
                return false;
            }
            if (wait != WAIT_OBJECT_0)
            {
                const DWORD waitError = GetLastError();
                CancelIoEx(pipe, overlapped);
                GetOverlappedResult(pipe, overlapped, transferred, TRUE);
                if (failure) *failure = waitError;
                return false;
            }
            const BOOL ok = GetOverlappedResult(pipe, overlapped, transferred, FALSE);
            if (!ok && failure) *failure = GetLastError();
            return ok != FALSE;
        }

        bool QueryServerUserSid(HANDLE pipe, BYTE* userSid, DWORD* userSidBytes) noexcept
        {
            if (!pipe || pipe == INVALID_HANDLE_VALUE || !userSid || !userSidBytes) return false;
            try
            {
                ULONG processId = 0;
                if (!GetNamedPipeServerProcessId(pipe, &processId)) return false;

                ScopedHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
                if (!process.get()) return false;
                HANDLE token = nullptr;
                const BOOL tokenOpened = OpenProcessToken(process.get(), TOKEN_QUERY, &token);
                if (!tokenOpened || !token) return false;
                ScopedHandle tokenHandle(token);

                DWORD required = 0;
                GetTokenInformation(tokenHandle.get(), TokenUser, nullptr, 0, &required);
                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0)
                    return false;
                std::vector<BYTE> tokenInformation(required);
                if (!GetTokenInformation(tokenHandle.get(), TokenUser, tokenInformation.data(),
                                          required, &required))
                    return false;

                const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenInformation.data());
                if (!tokenUser->User.Sid || !IsValidSid(tokenUser->User.Sid)) return false;
                const DWORD requiredSidBytes = GetLengthSid(tokenUser->User.Sid);
                if (requiredSidBytes == 0 || requiredSidBytes > *userSidBytes) return false;
                if (!CopySid(requiredSidBytes, userSid, tokenUser->User.Sid)) return false;
                *userSidBytes = requiredSidBytes;
                return true;
            }
            catch (...)
            {
                return false;
            }
        }

        bool VerifyServerIsLocalSystem(HANDLE pipe, ServerIdentityProvider identityProvider) noexcept
        {
            if (!identityProvider) return false;
            BYTE serverSid[SECURITY_MAX_SID_SIZE] = {};
            DWORD serverSidBytes = sizeof(serverSid);
            if (!identityProvider(pipe, serverSid, &serverSidBytes) ||
                serverSidBytes == 0 || serverSidBytes > sizeof(serverSid) ||
                !IsValidSid(serverSid)) return false;

            BYTE systemSid[SECURITY_MAX_SID_SIZE] = {};
            DWORD systemSidBytes = sizeof(systemSid);
            if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid, &systemSidBytes))
                return false;
            return EqualSid(serverSid, systemSid) != FALSE;
        }

        bool ReadOverlapped(HANDLE pipe, void* buffer, DWORD capacity, ULONGLONG deadline,
                            DWORD* transferred, DWORD* failure) noexcept
        {
            if (transferred) *transferred = 0;
            if (failure) *failure = ERROR_SUCCESS;
            HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!event)
            {
                if (failure) *failure = GetLastError();
                return false;
            }

            OVERLAPPED overlapped{};
            overlapped.hEvent = event;
            DWORD bytes = 0;
            BOOL ok = ReadFile(pipe, buffer, capacity, &bytes, &overlapped);
            DWORD error = ok ? ERROR_SUCCESS : GetLastError();
            if (!ok && error == ERROR_IO_PENDING)
            {
                const ULONGLONG now = GetTickCount64();
                const DWORD remaining = now < deadline
                    ? static_cast<DWORD>(deadline - now) : 0;
                if (remaining == 0)
                {
                    CancelIoEx(pipe, &overlapped);
                    GetOverlappedResult(pipe, &overlapped, &bytes, TRUE);
                    error = ERROR_SEM_TIMEOUT;
                    ok = FALSE;
                }
                else
                {
                    ok = WaitOverlapped(pipe, &overlapped, remaining, &bytes, &error);
                }
            }
            CloseHandle(event);
            if (transferred) *transferred = bytes;
            if (!ok && failure) *failure = error;
            return ok != FALSE;
        }

        void SetFailure(PipeResult* result, PipeResultKind kind, const wchar_t* message) noexcept
        {
            if (!result) return;
            result->kind = kind;
            try { result->error = message; }
            catch (...) { result->error.clear(); }
        }

        bool Exchange(const wchar_t* pipeName, const char* request, DWORD requestBytes,
                      std::string* response, PipeResult* failure,
                      ServerIdentityProvider identityProvider) noexcept
        {
            if (!pipeName || !response || !failure || requestBytes == 0 ||
                requestBytes > kMaxMessageBytes)
            {
                SetFailure(failure, PipeResultKind::Error, L"invalid_request");
                return false;
            }

            if (!WaitNamedPipeW(pipeName, kConnectTimeoutMs))
            {
                SetFailure(failure, PipeResultKind::ServiceUnavailable, L"connect_timeout");
                return false;
            }

            HANDLE pipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                      OPEN_EXISTING, FILE_FLAG_OVERLAPPED |
                                      SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
            if (pipe == INVALID_HANDLE_VALUE)
            {
                SetFailure(failure, PipeResultKind::ServiceUnavailable, L"connect_failed");
                return false;
            }

            if (!VerifyServerIsLocalSystem(pipe, identityProvider))
            {
                CloseHandle(pipe);
                SetFailure(failure, PipeResultKind::ServiceUnavailable, L"untrusted_server");
                return false;
            }

            DWORD mode = PIPE_READMODE_MESSAGE;
            const bool messageMode = SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr) != FALSE;

            HANDLE writeEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!writeEvent)
            {
                CloseHandle(pipe);
                SetFailure(failure, PipeResultKind::Error, L"write_event_failed");
                return false;
            }
            OVERLAPPED writeOverlapped{};
            writeOverlapped.hEvent = writeEvent;
            DWORD written = 0;
            BOOL writeOk = WriteFile(pipe, request, requestBytes, &written, &writeOverlapped);
            if (!writeOk && GetLastError() == ERROR_IO_PENDING)
                writeOk = WaitOverlapped(pipe, &writeOverlapped, kWriteTimeoutMs, &written, nullptr);
            CloseHandle(writeEvent);
            if (!writeOk || written != requestBytes)
            {
                CloseHandle(pipe);
                SetFailure(failure, PipeResultKind::ServiceUnavailable, L"write_failed");
                return false;
            }

            std::array<char, kMaxMessageBytes + 1> responseBuffer{};
            const ULONGLONG readDeadline = GetTickCount64() + kReadTimeoutMs;
            size_t responseBytes = 0;
            DWORD readError = ERROR_SUCCESS;
            if (messageMode)
            {
                DWORD read = 0;
                const bool readOk = ReadOverlapped(pipe, responseBuffer.data(),
                    static_cast<DWORD>(responseBuffer.size()), readDeadline, &read, &readError);
                if (readOk)
                {
                    responseBytes = read;
                }
                else if (readError == ERROR_MORE_DATA || read > kMaxMessageBytes)
                {
                    CloseHandle(pipe);
                    SetFailure(failure, PipeResultKind::Error, L"oversize_response");
                    return false;
                }
            }
            else
            {
                bool eof = false;
                while (!eof && responseBytes <= kMaxMessageBytes)
                {
                    char chunk[512] = {};
                    const DWORD capacity = static_cast<DWORD>((std::min)(
                        sizeof(chunk), kMaxMessageBytes + 1 - responseBytes));
                    DWORD read = 0;
                    if (ReadOverlapped(pipe, chunk, capacity, readDeadline, &read, &readError))
                    {
                        if (read == 0)
                        {
                            eof = true;
                            break;
                        }
                        if (responseBytes + read > kMaxMessageBytes)
                        {
                            readError = ERROR_MORE_DATA;
                            break;
                        }
                        CopyMemory(responseBuffer.data() + responseBytes, chunk, read);
                        responseBytes += read;
                    }
                    else if (readError == ERROR_BROKEN_PIPE || readError == ERROR_HANDLE_EOF ||
                             readError == ERROR_PIPE_NOT_CONNECTED)
                    {
                        eof = true;
                    }
                    else
                    {
                        break;
                    }
                }
                if (!eof && readError == ERROR_SUCCESS) readError = ERROR_MORE_DATA;
            }
            CloseHandle(pipe);

            if (readError == ERROR_MORE_DATA || responseBytes > kMaxMessageBytes)
            {
                SetFailure(failure, PipeResultKind::Error, L"oversize_response");
                return false;
            }
            if ((readError != ERROR_SUCCESS && readError != ERROR_BROKEN_PIPE &&
                 readError != ERROR_HANDLE_EOF && readError != ERROR_PIPE_NOT_CONNECTED) ||
                responseBytes == 0)
            {
                SetFailure(failure, readError == ERROR_SEM_TIMEOUT
                    ? PipeResultKind::ServiceUnavailable : PipeResultKind::Error, L"read_failed");
                return false;
            }

            try
            {
                response->assign(responseBuffer.data(), responseBytes);
            }
            catch (...)
            {
                SetFailure(failure, PipeResultKind::Error, L"out_of_memory");
                return false;
            }
            return true;
        }

        PipeResult ExchangeAndParse(const wchar_t* pipeName, const char* request,
                                    DWORD requestBytes, bool consume,
                                    ServerIdentityProvider identityProvider) noexcept
        {
            try
            {
                std::string response;
                PipeResult failure;
                if (!Exchange(pipeName, request, requestBytes, &response, &failure,
                              identityProvider)) return failure;
                return consume ? ParseConsumeResponse(response) : ParseStatusResponse(response);
            }
            catch (...)
            {
                PipeResult failure;
                failure.kind = PipeResultKind::Error;
                return failure;
            }
        }
    }

    PipeResult ParseStatusResponse(std::string_view json) noexcept
    {
        try { return ParseResponse(json, false); }
        catch (...) { PipeResult result; result.error = L"bad_response"; return result; }
    }

    PipeResult ParseConsumeResponse(std::string_view json) noexcept
    {
        try { return ParseResponse(json, true); }
        catch (...) { PipeResult result; result.error = L"bad_response"; return result; }
    }

    PipeResult PipeClient::QueryStatus() noexcept
    {
        static constexpr char request[] = "{\"v\":1,\"op\":\"status\"}";
        return ExchangeAndParse(kPipeName, request, static_cast<DWORD>(sizeof(request) - 1),
                                false, QueryServerUserSid);
    }

    IAuthService& DefaultAuthService() noexcept
    {
        static PipeAuthService service;
        return service;
    }

    bool BuildConsumeRequest(std::string_view nonce, std::string* request) noexcept
    {
        if (!request) return false;
        try
        {
            request->clear();
            if (!IsNonce(nonce)) return false;
            request->assign("{\"v\":1,\"op\":\"consume\",\"nonce\":\"");
            request->append(nonce.data(), nonce.size());
            request->append("\"}");
            return true;
        }
        catch (...)
        {
            request->clear();
            return false;
        }
    }

    PipeResult PipeClient::Consume(std::string_view nonce) noexcept
    {
        try
        {
            std::string request;
            if (!BuildConsumeRequest(nonce, &request))
            {
                PipeResult result;
                result.kind = PipeResultKind::Error;
                try { result.error = L"invalid_nonce"; } catch (...) { }
                return result;
            }
            return ExchangeAndParse(kPipeName, request.data(), static_cast<DWORD>(request.size()),
                                    true, QueryServerUserSid);
        }
        catch (...)
        {
            PipeResult result;
            result.kind = PipeResultKind::Error;
            return result;
        }
    }

#ifdef NFC_AUTH_TESTING
    PipeResult Testing::Exchange(const wchar_t* pipeName, std::string_view request,
                                 bool consume,
                                 Testing::ServerIdentityProvider identityProvider) noexcept
    {
        try
        {
            std::string response;
            PipeResult failure;
            if (request.size() > (std::numeric_limits<DWORD>::max)() ||
                !NfcAuth::Exchange(pipeName, request.data(), static_cast<DWORD>(request.size()),
                                   &response, &failure, identityProvider)) return failure;
            return consume ? ParseConsumeResponse(response) : ParseStatusResponse(response);
        }
        catch (...)
        {
            PipeResult failure;
            failure.kind = PipeResultKind::Error;
            return failure;
        }
    }
#endif
}
