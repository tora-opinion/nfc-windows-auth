#pragma once

namespace NfcAuth
{
    void ModuleObjectCreated() noexcept;
    void ModuleObjectDestroyed() noexcept;
    void ModuleWorkerStarted() noexcept;
    void ModuleWorkerStopped() noexcept;
}
