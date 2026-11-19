#pragma once

#include "PipeClient.h"

#include <string>
#include <string_view>

namespace NfcAuth
{
    enum class SubmitAction
    {
        NoTap,
        PasswordRequired,
        RequestConsume,
        WaitForConsume,
        ConsumeFailed,
        Serialize
    };

    struct SubmitSnapshot
    {
        bool tapCurrent = false;
        bool passwordPresent = false;
        bool consumed = false;
        bool consumeDone = false;
        bool consumeSucceeded = false;
        bool consumeRequested = false;
        bool consumeInFlight = false;
        std::string_view currentNonce;
        std::string_view pendingNonce;
    };

    struct SubmitDecision
    {
        SubmitAction action = SubmitAction::NoTap;
        std::string nonce;
    };

    SubmitDecision DecideSubmission(const SubmitSnapshot& snapshot);
    bool IsConsumeAccepted(const PipeResult& result) noexcept;
    bool TakePasswordForSerialization(const SubmitDecision& decision,
                                     std::wstring& storedPassword,
                                     std::wstring* serializationPassword) noexcept;
}
