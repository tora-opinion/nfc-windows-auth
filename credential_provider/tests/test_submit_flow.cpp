#include "../src/KerbPack.h"
#include "../src/SubmitFlow.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <string>
#include <vector>

using namespace NfcAuth;

namespace
{
    class FakeAuthService final : public IAuthService
    {
    public:
        PipeResult status;
        PipeResult consumeResult;
        unsigned int statusCalls = 0;
        unsigned int consumeCalls = 0;
        std::vector<std::string> consumedNonces;

        PipeResult QueryStatus() noexcept override
        {
            ++statusCalls;
            return status;
        }

        PipeResult Consume(std::string_view nonce) noexcept override
        {
            ++consumeCalls;
            try { consumedNonces.emplace_back(nonce); }
            catch (...) { }
            return consumeResult;
        }
    };

    SubmitSnapshot CurrentTap(std::string_view nonce)
    {
        SubmitSnapshot snapshot;
        snapshot.tapCurrent = true;
        snapshot.passwordPresent = true;
        snapshot.currentNonce = nonce;
        return snapshot;
    }

    void TestSuccessfulConsumeProducesSerializationAndWipesPassword()
    {
        FakeAuthService service;
        service.status.kind = PipeResultKind::Tap;
        service.consumeResult.kind = PipeResultKind::Consumed;
        assert(service.QueryStatus().kind == PipeResultKind::Tap);
        SubmitSnapshot snapshot = CurrentTap("0123456789abcdef0123456789abcdef");

        SubmitDecision first = DecideSubmission(snapshot);
        assert(first.action == SubmitAction::RequestConsume);
        assert(first.nonce == snapshot.currentNonce);
        const PipeResult consume = service.Consume(first.nonce);
        assert(IsConsumeAccepted(consume));

        snapshot.consumeDone = true;
        snapshot.consumeSucceeded = IsConsumeAccepted(consume);
        snapshot.consumed = snapshot.consumeSucceeded;
        SubmitDecision second = DecideSubmission(snapshot);
        assert(second.action == SubmitAction::Serialize);

        std::wstring storedPassword = L"test-password";
        std::wstring serializationPassword;
        assert(TakePasswordForSerialization(second, storedPassword, &serializationPassword));
        assert(storedPassword.empty());
        assert(serializationPassword == L"test-password");

        BYTE* buffer = nullptr;
        ULONG bufferSize = 0;
        assert(SUCCEEDED(PackKerbLogon(L"DOMAIN", L"user", serializationPassword,
                                       KerbScenario::Logon, &buffer, &bufferSize)));
        assert(buffer != nullptr && bufferSize > 0);
        SecureZeroPassword(serializationPassword);
        SecureFreeKerbBuffer(buffer, bufferSize);
        assert(service.statusCalls == 1);
        assert(service.consumeCalls == 1);
    }

    void TestConsumeFailuresNeverSerialize()
    {
        const PipeResult failures[] =
        {
            { PipeResultKind::ServiceUnavailable, {}, 0, {}, L"service_down" },
            { PipeResultKind::NoTap, {}, 0, {}, L"expired" },
            { PipeResultKind::Error, {}, 0, {}, L"bad_nonce" }
        };

        for (const PipeResult& failure : failures)
        {
            FakeAuthService service;
            service.consumeResult = failure;
            SubmitSnapshot snapshot = CurrentTap("0123456789abcdef0123456789abcdef");
            const SubmitDecision initial = DecideSubmission(snapshot);
            assert(initial.action == SubmitAction::RequestConsume);
            const PipeResult consumed = service.Consume(initial.nonce);
            assert(!IsConsumeAccepted(consumed));

            snapshot.consumeDone = true;
            snapshot.consumeSucceeded = IsConsumeAccepted(consumed);
            snapshot.consumed = snapshot.consumeSucceeded;
            const SubmitDecision afterFailure = DecideSubmission(snapshot);
            assert(afterFailure.action == SubmitAction::ConsumeFailed);

            std::wstring storedPassword = L"test-password";
            std::wstring serializationPassword;
            assert(!TakePasswordForSerialization(afterFailure, storedPassword,
                                                 &serializationPassword));
            assert(storedPassword == L"test-password");
            BYTE* buffer = nullptr;
            ULONG bufferSize = 0;
            assert(buffer == nullptr && bufferSize == 0);
            assert(service.consumeCalls == 1);
        }
    }

    void TestEmptyPasswordDoesNotConsume()
    {
        FakeAuthService service;
        SubmitSnapshot snapshot = CurrentTap("0123456789abcdef0123456789abcdef");
        snapshot.passwordPresent = false;
        const SubmitDecision decision = DecideSubmission(snapshot);
        assert(decision.action == SubmitAction::PasswordRequired);
        if (decision.action == SubmitAction::RequestConsume)
            service.Consume(decision.nonce);
        assert(service.consumeCalls == 0);
    }

    void TestNewTapDoesNotReuseOlderPendingNonce()
    {
        FakeAuthService service;
        service.consumeResult.kind = PipeResultKind::Consumed;
        SubmitSnapshot snapshot = CurrentTap("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        snapshot.consumeRequested = true;
        snapshot.consumeInFlight = true;
        snapshot.pendingNonce = "11111111111111111111111111111111";

        const SubmitDecision decision = DecideSubmission(snapshot);
        assert(decision.action == SubmitAction::RequestConsume);
        assert(decision.nonce == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        service.Consume(decision.nonce);
        assert(service.consumedNonces.size() == 1);
        assert(service.consumedNonces[0] == snapshot.currentNonce);
    }
}

int main()
{
    TestSuccessfulConsumeProducesSerializationAndWipesPassword();
    TestConsumeFailuresNeverSerialize();
    TestEmptyPasswordDoesNotConsume();
    TestNewTapDoesNotReuseOlderPendingNonce();
    return 0;
}
