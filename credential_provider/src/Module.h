#pragma once

#include <windows.h>

namespace NfcAuth
{
    // The DLL's own instance handle, used to load the tile artwork.
    HINSTANCE ModuleInstance() noexcept;

    void ModuleObjectCreated() noexcept;
    void ModuleObjectDestroyed() noexcept;
    void ModuleWorkerStarted() noexcept;
    void ModuleWorkerStopped() noexcept;
}
