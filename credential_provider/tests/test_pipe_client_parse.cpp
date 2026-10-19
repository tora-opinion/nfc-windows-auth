#include "../src/PipeClient.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <string>
#include <vector>

using namespace NfcAuth;

namespace
{
    void TestStatusResponses()
    {
        PipeResult result = ParseStatusResponse("{\"v\":1,\"ok\":true,\"tap\":false}");
        assert(result.kind == PipeResultKind::NoTap);

        result = ParseStatusResponse(
            "{\"v\":1,\"ok\":true,\"tap\":true,\"user\":\"DOMAIN\\\\suger\","
            "\"ttl_ms\":30000,\"nonce\":\"0123456789abcdef0123456789abcdef\"}");
        assert(result.kind == PipeResultKind::Tap);
        assert(result.user == L"DOMAIN\\suger");
        assert(result.ttlMs == 30000);
        assert(result.nonce == "0123456789abcdef0123456789abcdef");

        result = ParseStatusResponse(
            "{\"v\":1,\"ok\":true,\"tap\":true,\"user\":null,\"ttl_ms\":5000,"
            "\"nonce\":\"ABCDEF0123456789abcdef0123456789\"}");
        assert(result.kind == PipeResultKind::Tap);
        assert(result.nonce == "ABCDEF0123456789abcdef0123456789");

        result = ParseStatusResponse(
            "{\"nonce\":\"0123456789abcdef0123456789abcdef\",\"ttl_ms\":10000,"
            "\"user\":null,\"tap\":true,\"ok\":true,\"v\":1}");
        assert(result.kind == PipeResultKind::Tap);
        assert(result.user.empty());

        result = ParseStatusResponse(
            "{\"v\":1,\"ok\":true,\"tap\":true,\"user\":\"\\u6771\\u4eac\\\\user\","
            "\"ttl_ms\":5000,\"nonce\":\"abcdef0123456789abcdef0123456789\"}");
        assert(result.kind == PipeResultKind::Tap);
        assert(result.user == L"東京\\user");

        result = ParseStatusResponse(
            "{\"v\":1,\"ok\":false,\"error\":\"bad_request\"}");
        assert(result.kind == PipeResultKind::Error);
        assert(result.error == L"bad_request");

        std::string exactLimit = "{\"v\":1,\"ok\":true,\"tap\":false}";
        exactLimit.append(4096 - exactLimit.size(), ' ');
        assert(exactLimit.size() == 4096);
        assert(ParseStatusResponse(exactLimit).kind == PipeResultKind::NoTap);
    }

    void TestConsumeResponses()
    {
        PipeResult result = ParseConsumeResponse("{\"v\":1,\"ok\":true}");
        assert(result.kind == PipeResultKind::Consumed);

        result = ParseConsumeResponse("{\"v\":1,\"ok\":false,\"error\":\"no_tap\"}");
        assert(result.kind == PipeResultKind::NoTap && result.error == L"no_tap");
        result = ParseConsumeResponse("{\"v\":1,\"ok\":false,\"error\":\"expired\"}");
        assert(result.kind == PipeResultKind::NoTap && result.error == L"expired");
        result = ParseConsumeResponse("{\"v\":1,\"ok\":false,\"error\":\"bad_nonce\"}");
        assert(result.kind == PipeResultKind::Error && result.error == L"bad_nonce");
        result = ParseConsumeResponse("{\"v\":1,\"ok\":false,\"error\":\"bad_request\"}");
        assert(result.kind == PipeResultKind::Error && result.error == L"bad_request");
    }

    void TestMalformedAndHostileResponses()
    {
        const char* invalid[] =
        {
            "",
            "{",
            "{\"v\":1,\"ok\":true,\"tap\":false,,}",
            "{\"v\":2,\"ok\":true,\"tap\":false}",
            "{\"v\":1,\"v\":1,\"ok\":true,\"tap\":false}",
            "{\"v\":1,\"ok\":true,\"ok\":true,\"tap\":false}",
            "{\"v\":1.0,\"ok\":true,\"tap\":false}",
            "{\"v\":1,\"ok\":true,\"tap\":false,\"extra\":0}",
            "{\"v\":1,\"ok\":true,\"tap\":true,\"user\":null,\"ttl_ms\":5000,\"nonce\":\"short\"}",
            "{\"v\":1,\"ok\":true,\"tap\":true,\"user\":null,\"ttl_ms\":5000,\"nonce\":\"0123456789abcdef0123456789abcde\"}",
            "{\"v\":1,\"ok\":true,\"tap\":true,\"user\":null,\"ttl_ms\":5000,\"nonce\":\"0123456789abcdef0123456789abcdeg\"}",
            "{\"v\":1,\"ok\":true,\"tap\":true,\"user\":\"x\",\"ttl_ms\":120001,\"nonce\":\"0123456789abcdef0123456789abcdef\"}",
            "{\"v\":1,\"ok\":true,\"tap\":true,\"user\":\"\\ud800\",\"ttl_ms\":5000,\"nonce\":\"0123456789abcdef0123456789abcdef\"}",
            "{\"v\":1,\"ok\":false,\"error\":\"no_tap\"}",
            "{\"v\":1,\"ok\":true,\"tap\":true,\"user\":\"\\u000a\",\"ttl_ms\":5000,\"nonce\":\"0123456789abcdef0123456789abcdef\"}",
            "{\"v\":1,\"ok\":false,\"error\":\"anything_else\"}",
            "{\"v\":1,\"ok\":true,\"tap\":false} trailing",
            "{\"v\":1,\"ok\":true,\"tap\":false,\"nested\":[]}",
            "{\"v\":1,\"ok\":true,\"tap\":false,\"user\":null}",
            "{\"v\":1,\"ok\":true}"
        };
        for (const char* json : invalid)
        {
            assert(ParseStatusResponse(json).kind == PipeResultKind::Error);
        }
        assert(ParseConsumeResponse("{\"v\":1,\"ok\":true,\"tap\":false}").kind == PipeResultKind::Error);

        std::string oversized = "{\"v\":1,\"ok\":true,\"tap\":false}";
        oversized.append(4097 - oversized.size(), ' ');
        assert(oversized.size() == 4097);
        assert(ParseStatusResponse(oversized).kind == PipeResultKind::Error);

        std::string invalidUtf8 = "{\"v\":1,\"ok\":true,\"tap\":true,\"user\":\"";
        invalidUtf8.push_back(static_cast<char>(0xFF));
        invalidUtf8 += "\",\"ttl_ms\":5000,\"nonce\":\"0123456789abcdef0123456789abcdef\"}";
        assert(ParseStatusResponse(invalidUtf8).kind == PipeResultKind::Error);

        assert(ParseStatusResponse(
            "{\"v\":1,\"ok\":true,\"tap\":true,\"user\":\"\\u0000\","
            "\"ttl_ms\":5000,\"nonce\":\"0123456789abcdef0123456789abcdef\"}").kind == PipeResultKind::Error);
    }

    bool TrustedIdentity(HANDLE, BYTE* userSid, DWORD* userSidBytes) noexcept
    {
        if (!userSid || !userSidBytes) return false;
        return CreateWellKnownSid(WinLocalSystemSid, nullptr, userSid, userSidBytes) != FALSE;
    }

    bool NonSystemIdentity(HANDLE, BYTE* userSid, DWORD* userSidBytes) noexcept
    {
        if (!userSid || !userSidBytes) return false;
        return CreateWellKnownSid(WinWorldSid, nullptr, userSid, userSidBytes) != FALSE;
    }

    struct PipeServerHarness
    {
        HANDLE pipe = INVALID_HANDLE_VALUE;
        HANDLE readyEvent = nullptr;
        std::string response;
        bool expectRequest = true;
        bool connectSucceeded = false;
        bool readCompleted = false;
        DWORD readError = ERROR_SUCCESS;
        bool sawRequest = false;
        bool requestValid = false;
        bool closedWithoutWrite = false;
    };

    bool CompleteServerIo(HANDLE pipe, OVERLAPPED* overlapped, BOOL result,
                          DWORD* transferred, DWORD* failure = nullptr) noexcept
    {
        if (result)
        {
            if (failure) *failure = ERROR_SUCCESS;
            return true;
        }
        DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING)
        {
            if (failure) *failure = error;
            return false;
        }
        if (WaitForSingleObject(overlapped->hEvent, 5000) != WAIT_OBJECT_0)
        {
            if (failure) *failure = WAIT_TIMEOUT;
            return false;
        }
        const BOOL completed = GetOverlappedResult(pipe, overlapped, transferred, FALSE);
        if (!completed) error = GetLastError();
        if (failure) *failure = completed ? ERROR_SUCCESS : error;
        return completed != FALSE;
    }

    DWORD WINAPI RunPipeServer(void* context) noexcept
    {
        auto* server = static_cast<PipeServerHarness*>(context);
        OVERLAPPED connect{};
        connect.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!connect.hEvent)
        {
            SetEvent(server->readyEvent);
            CloseHandle(server->pipe);
            return 1;
        }
        BOOL connected = ConnectNamedPipe(server->pipe, &connect);
        DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();
        if (!connected && connectError == ERROR_IO_PENDING)
        {
            SetEvent(server->readyEvent);
            DWORD ignored = 0;
            connected = CompleteServerIo(server->pipe, &connect, FALSE, &ignored);
        }
        else
        {
            SetEvent(server->readyEvent);
            if (!connected && connectError == ERROR_PIPE_CONNECTED) connected = TRUE;
        }
        CloseHandle(connect.hEvent);
        server->connectSucceeded = connected != FALSE;
        if (!server->connectSucceeded)
        {
            CloseHandle(server->pipe);
            return 1;
        }

        char request[128] = {};
        DWORD received = 0;
        OVERLAPPED readOperation{};
        readOperation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!readOperation.hEvent)
        {
            CloseHandle(server->pipe);
            return 1;
        }
        const BOOL readOk = CompleteServerIo(server->pipe, &readOperation,
            ReadFile(server->pipe, request, sizeof(request), &received, &readOperation),
            &received, &server->readError);
        server->readCompleted = readOk || server->readError != WAIT_TIMEOUT;
        CloseHandle(readOperation.hEvent);
        if (server->expectRequest)
        {
            server->sawRequest = readOk && received > 0;
            server->requestValid = server->sawRequest &&
                std::string(request, received) == "{\"v\":1,\"op\":\"status\"}";
            if (server->sawRequest && !server->response.empty())
            {
                DWORD written = 0;
                OVERLAPPED writeOperation{};
                writeOperation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
                if (writeOperation.hEvent)
                {
                    CompleteServerIo(server->pipe, &writeOperation,
                        WriteFile(server->pipe, server->response.data(),
                            static_cast<DWORD>(server->response.size()), &written, &writeOperation),
                        &written);
                    CloseHandle(writeOperation.hEvent);
                }
                FlushFileBuffers(server->pipe);
            }
        }
        else
        {
            server->sawRequest = received > 0;
            server->closedWithoutWrite = !readOk && received == 0 &&
                (server->readError == ERROR_BROKEN_PIPE || server->readError == ERROR_NO_DATA ||
                 server->readError == ERROR_PIPE_NOT_CONNECTED);
        }
        DisconnectNamedPipe(server->pipe);
        CloseHandle(server->pipe);
        return 0;
    }

    HANDLE CreateTestPipe(const wchar_t* name, bool messageType)
    {
        const DWORD mode = messageType
            ? PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT
            : PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT;
        return CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, mode, 1,
            4096, 4096, 0, nullptr);
    }

    void RunExchangeHarness(bool messageType)
    {
        wchar_t name[128] = {};
        swprintf_s(name, L"\\\\.\\pipe\\NfcAuthTapTest-%lu-%lu",
            GetCurrentProcessId(), GetTickCount());
        PipeServerHarness server;
        server.pipe = CreateTestPipe(name, messageType);
        server.readyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        assert(server.pipe != INVALID_HANDLE_VALUE);
        assert(server.readyEvent != nullptr);
        server.response = "{\"v\":1,\"ok\":true,\"tap\":false}";
        if (!messageType)
            server.response = "{\"v\":1,\"ok\":true,\"tap\":false" +
                std::string(600, ' ') + "}";
        HANDLE thread = CreateThread(nullptr, 0, RunPipeServer, &server, 0, nullptr);
        assert(thread != nullptr);
        assert(WaitForSingleObject(server.readyEvent, 5000) == WAIT_OBJECT_0);

        const PipeResult result = Testing::Exchange(name,
            "{\"v\":1,\"op\":\"status\"}", false, TrustedIdentity);
        assert(result.kind == PipeResultKind::NoTap);
        assert(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0);
        assert(server.connectSucceeded);
        assert(server.requestValid);
        CloseHandle(thread);
        CloseHandle(server.readyEvent);
    }

    void TestServerIdentityIsVerifiedBeforeWrite()
    {
        wchar_t name[128] = {};
        swprintf_s(name, L"\\\\.\\pipe\\NfcAuthTapReject-%lu-%lu",
            GetCurrentProcessId(), GetTickCount());
        PipeServerHarness server;
        server.pipe = CreateTestPipe(name, true);
        server.readyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        server.expectRequest = false;
        assert(server.pipe != INVALID_HANDLE_VALUE);
        assert(server.readyEvent != nullptr);
        HANDLE thread = CreateThread(nullptr, 0, RunPipeServer, &server, 0, nullptr);
        assert(thread != nullptr);
        assert(WaitForSingleObject(server.readyEvent, 5000) == WAIT_OBJECT_0);

        const PipeResult result = Testing::Exchange(name,
            "{\"v\":1,\"op\":\"status\"}", false, NonSystemIdentity);
        assert(result.kind == PipeResultKind::ServiceUnavailable);
        assert(result.error == L"untrusted_server");
        assert(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0);
        assert(server.connectSucceeded);
        assert(server.readCompleted);
        assert(!server.sawRequest);
        assert(server.closedWithoutWrite);
        CloseHandle(thread);
        CloseHandle(server.readyEvent);
    }

    void TestConsumeNonceValidationAndPreservation()
    {
        std::string request;
        const std::string upper = "ABCDEF0123456789abcdef0123456789";
        assert(BuildConsumeRequest(upper, &request));
        assert(request == "{\"v\":1,\"op\":\"consume\",\"nonce\":\"" + upper + "\"}");

        assert(BuildConsumeRequest("0123456789abcdef0123456789abcdef", &request));
        assert(!BuildConsumeRequest("0123456789abcdef0123456789abcde", &request));
        assert(!BuildConsumeRequest("0123456789abcdef0123456789abcdeg", &request));
    }
}

int main()
{
    TestStatusResponses();
    TestConsumeResponses();
    TestMalformedAndHostileResponses();
    TestConsumeNonceValidationAndPreservation();
    RunExchangeHarness(true);
    RunExchangeHarness(false);
    TestServerIdentityIsVerifiedBeforeWrite();
    return 0;
}
