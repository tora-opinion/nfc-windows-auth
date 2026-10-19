#include "SubmitFlow.h"

#include "KerbPack.h"

namespace NfcAuth
{
    SubmitDecision DecideSubmission(const SubmitSnapshot& snapshot)
    {
        SubmitDecision decision;
        if (!snapshot.tapCurrent)
        {
            decision.action = SubmitAction::NoTap;
        }
        else if (!snapshot.passwordPresent)
        {
            decision.action = SubmitAction::PasswordRequired;
        }
        else if (snapshot.consumed)
        {
            decision.action = SubmitAction::Serialize;
        }
        else if (snapshot.consumeDone && !snapshot.consumeSucceeded)
        {
            decision.action = SubmitAction::ConsumeFailed;
        }
        else if ((snapshot.consumeRequested || snapshot.consumeInFlight) &&
                 snapshot.pendingNonce == snapshot.currentNonce)
        {
            decision.action = SubmitAction::WaitForConsume;
        }
        else
        {
            decision.action = SubmitAction::RequestConsume;
            decision.nonce.assign(snapshot.currentNonce);
        }
        return decision;
    }

    bool IsConsumeAccepted(const PipeResult& result) noexcept
    {
        return result.kind == PipeResultKind::Consumed;
    }

    bool TakePasswordForSerialization(const SubmitDecision& decision,
                                     std::wstring& storedPassword,
                                     std::wstring* serializationPassword) noexcept
    {
        if (!serializationPassword || decision.action != SubmitAction::Serialize ||
            storedPassword.empty()) return false;
        try
        {
            *serializationPassword = storedPassword;
            SecureZeroPassword(storedPassword);
            storedPassword.clear();
            return true;
        }
        catch (...)
        {
            SecureZeroPassword(*serializationPassword);
            serializationPassword->clear();
            return false;
        }
    }
}
