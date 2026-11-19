#include "Credential.h"

#include "KerbPack.h"
#include "Module.h"
#include "PipeClient.h"
#include "Provider.h"
#include "Strings.h"
#include "SubmitFlow.h"

#include <ntsecapi.h>
#include <propkey.h>
#include <shlwapi.h>
#include <algorithm>
#include <new>
#include <utility>

namespace NfcAuth
{
    namespace
    {
        class SecureWString final
        {
        public:
            std::wstring value;
            ~SecureWString() { SecureZeroPassword(value); }
        };

        bool SplitIdentity(const std::wstring& identity, std::wstring* domain,
                           std::wstring* user)
        {
            if (!domain || !user || identity.empty() || identity.find(L'\0') != std::wstring::npos)
                return false;

            const size_t slash = identity.find(L'\\');
            if (slash != std::wstring::npos)
            {
                if (slash == 0 || slash + 1 == identity.size() ||
                    identity.find(L'\\', slash + 1) != std::wstring::npos) return false;
                *domain = identity.substr(0, slash);
                *user = identity.substr(slash + 1);
                return true;
            }

            const size_t at = identity.find(L'@');
            if (at != std::wstring::npos)
            {
                if (at == 0 || at + 1 == identity.size() ||
                    identity.find(L'@', at + 1) != std::wstring::npos) return false;
                *user = identity.substr(0, at);
                *domain = identity.substr(at + 1);
                return true;
            }

            domain->clear();
            *user = identity;
            return true;
        }

        enum class UnlockUserResult
        {
            Found,
            Missing,
            Ambiguous
        };

        UnlockUserResult GetUnlockUser(ICredentialProviderUserArray* users,
                                       std::wstring* identity)
        {
            if (!users || !identity) return UnlockUserResult::Missing;
            DWORD count = 0;
            if (FAILED(users->GetCount(&count)) || count == 0) return UnlockUserResult::Missing;
            if (count != 1) return UnlockUserResult::Ambiguous;

            ICredentialProviderUser* user = nullptr;
            if (FAILED(users->GetAt(0, &user)) || !user) return UnlockUserResult::Missing;
            PWSTR qualifiedName = nullptr;
            const HRESULT hr = user->GetStringValue(PKEY_Identity_QualifiedUserName, &qualifiedName);
            user->Release();
            if (FAILED(hr) || !qualifiedName) return UnlockUserResult::Missing;
            try
            {
                identity->assign(qualifiedName);
            }
            catch (...)
            {
                CoTaskMemFree(qualifiedName);
                return UnlockUserResult::Missing;
            }
            CoTaskMemFree(qualifiedName);
            return identity->empty() ? UnlockUserResult::Missing : UnlockUserResult::Found;
        }

        HRESULT LookupNegotiatePackage(ULONG* packageId) noexcept
        {
            if (!packageId) return E_POINTER;
            *packageId = 0;

            HANDLE lsa = nullptr;
            NTSTATUS status = LsaConnectUntrusted(&lsa);
            if (status != 0) return HRESULT_FROM_NT(status);
            if (!lsa) return E_FAIL;

            CHAR packageName[] = "Negotiate";
            LSA_STRING package{};
            package.Buffer = packageName;
            package.Length = static_cast<USHORT>(sizeof(packageName) - 1);
            package.MaximumLength = static_cast<USHORT>(sizeof(packageName));

            ULONG foundPackage = 0;
            status = LsaLookupAuthenticationPackage(lsa, &package, &foundPackage);
            const NTSTATUS deregisterStatus = LsaDeregisterLogonProcess(lsa);
            if (status != 0) return HRESULT_FROM_NT(status);
            if (deregisterStatus != 0) return HRESULT_FROM_NT(deregisterStatus);

            *packageId = foundPackage;
            return S_OK;
        }
    }

    Credential::Credential(IAuthService* authService) noexcept
        : refCount_(1), authService_(authService ? authService : &DefaultAuthService()),
          lockInitialized_(FALSE), scenario_(CPUS_INVALID), users_(nullptr),
          events_(nullptr), eventsStream_(nullptr), workerEvents_(nullptr),
          pendingEvents_(nullptr), pendingEventsStream_(nullptr), workerThreadId_(0),
          stopEvent_(nullptr), wakeEvent_(nullptr), pendingStopEvent_(nullptr),
          pendingWakeEvent_(nullptr), stopping_(true), workerRunning_(false),
          tapKnown_(false), tapTtlMs_(0), tapObservedAt_(0),
          consumeRequested_(false), consumeInFlight_(false), consumeDone_(false), consumeSucceeded_(false),
          consumed_(false), failureStatus_(false), passwordVisible_(false)
    {
        lockInitialized_ = InitializeCriticalSectionEx(&lock_, 0, 0) != FALSE;
        ModuleObjectCreated();
    }

    Credential::~Credential() noexcept
    {
        if (lockInitialized_)
        {
            EnterCriticalSection(&lock_);
            ClearPasswordLocked();
            ClearTapLocked();
            ICredentialProviderUserArray* users = users_;
            ICredentialProviderCredentialEvents* events = events_;
            ICredentialProviderCredentialEvents* workerEvents = workerEvents_;
            IStream* eventsStream = eventsStream_;
            ICredentialProviderCredentialEvents* pendingEvents = pendingEvents_;
            IStream* pendingEventsStream = pendingEventsStream_;
            HANDLE pendingStopEvent = pendingStopEvent_;
            HANDLE pendingWakeEvent = pendingWakeEvent_;
            users_ = nullptr;
            events_ = nullptr;
            workerEvents_ = nullptr;
            eventsStream_ = nullptr;
            pendingEvents_ = nullptr;
            pendingEventsStream_ = nullptr;
            pendingStopEvent_ = nullptr;
            pendingWakeEvent_ = nullptr;
            LeaveCriticalSection(&lock_);
            if (users) users->Release();
            if (events) events->Release();
            if (workerEvents) workerEvents->Release();
            if (eventsStream) eventsStream->Release();
            if (pendingEvents) pendingEvents->Release();
            if (pendingEventsStream) pendingEventsStream->Release();
            if (pendingStopEvent) CloseHandle(pendingStopEvent);
            if (pendingWakeEvent) CloseHandle(pendingWakeEvent);
            DeleteCriticalSection(&lock_);
        }
        ModuleObjectDestroyed();
    }

    HRESULT Credential::QueryInterface(REFIID riid, void** object)
    {
        if (!object) return E_POINTER;
        *object = nullptr;
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential)
            *object = static_cast<ICredentialProviderCredential*>(this);
        else if (riid == IID_IConnectableCredentialProviderCredential)
            *object = static_cast<IConnectableCredentialProviderCredential*>(this);
        else
            return E_NOINTERFACE;
        AddRef();
        return S_OK;
    }

    ULONG Credential::AddRef()
    {
        return static_cast<ULONG>(InterlockedIncrement(&refCount_));
    }

    ULONG Credential::Release()
    {
        const LONG refs = InterlockedDecrement(&refCount_);
        if (refs == 0) delete this;
        return static_cast<ULONG>(refs);
    }

    HRESULT Credential::Advise(ICredentialProviderCredentialEvents* events)
    {
        if (!events) return E_INVALIDARG;
        if (!lockInitialized_) return S_OK;

        EnterCriticalSection(&lock_);
        const bool workerAlreadyRunning = workerRunning_ && !stopping_;
        LeaveCriticalSection(&lock_);
        if (workerAlreadyRunning) UnAdvise();

        IStream* marshaledEvents = nullptr;
        const HRESULT marshalResult = CoMarshalInterThreadInterfaceInStream(
            IID_ICredentialProviderCredentialEvents, events, &marshaledEvents);
        if (FAILED(marshalResult))
        {
            if (marshaledEvents) marshaledEvents->Release();
            SetDisplayStatus(kStatusUnavailable, false);
            return S_OK;
        }

        HANDLE stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE wakeEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (!stopEvent || !wakeEvent)
        {
            if (stopEvent) CloseHandle(stopEvent);
            if (wakeEvent) CloseHandle(wakeEvent);
            if (marshaledEvents) marshaledEvents->Release();
            SetDisplayStatus(kStatusUnavailable, false);
            return S_OK;
        }

        events->AddRef();
        ICredentialProviderCredentialEvents* oldEvents = nullptr;
        IStream* oldStream = nullptr;
        ICredentialProviderCredentialEvents* stalePendingEvents = nullptr;
        IStream* stalePendingStream = nullptr;
        HANDLE stalePendingStopEvent = nullptr;
        HANDLE stalePendingWakeEvent = nullptr;
        EnterCriticalSection(&lock_);
        if (workerRunning_)
        {
            if (!stopping_ || pendingEvents_)
            {
                LeaveCriticalSection(&lock_);
                events->Release();
                marshaledEvents->Release();
                CloseHandle(stopEvent);
                CloseHandle(wakeEvent);
                return E_PENDING;
            }
            pendingEvents_ = events;
            pendingEventsStream_ = marshaledEvents;
            pendingStopEvent_ = stopEvent;
            pendingWakeEvent_ = wakeEvent;
            LeaveCriticalSection(&lock_);
            return S_OK;
        }
        oldEvents = events_;
        oldStream = eventsStream_;
        stalePendingEvents = pendingEvents_;
        stalePendingStream = pendingEventsStream_;
        stalePendingStopEvent = pendingStopEvent_;
        stalePendingWakeEvent = pendingWakeEvent_;
        pendingEvents_ = nullptr;
        pendingEventsStream_ = nullptr;
        pendingStopEvent_ = nullptr;
        pendingWakeEvent_ = nullptr;
        events_ = events;
        eventsStream_ = marshaledEvents;
        stopEvent_ = stopEvent;
        wakeEvent_ = wakeEvent;
        stopping_ = false;
        workerRunning_ = true;
        AddRef();
        ModuleWorkerStarted();
        LeaveCriticalSection(&lock_);
        if (oldEvents) oldEvents->Release();
        if (oldStream) oldStream->Release();
        if (stalePendingEvents) stalePendingEvents->Release();
        if (stalePendingStream) stalePendingStream->Release();
        if (stalePendingStopEvent) CloseHandle(stalePendingStopEvent);
        if (stalePendingWakeEvent) CloseHandle(stalePendingWakeEvent);

        HANDLE worker = CreateThread(nullptr, 0, WorkerEntry, this, 0, nullptr);
        if (!worker)
        {
            ModuleWorkerStopped();
            Release();
            EnterCriticalSection(&lock_);
            workerRunning_ = false;
            stopping_ = true;
            stopEvent_ = nullptr;
            wakeEvent_ = nullptr;
            IStream* unusedStream = eventsStream_;
            eventsStream_ = nullptr;
            ICredentialProviderCredentialEvents* unusedEvents = events_;
            events_ = nullptr;
            LeaveCriticalSection(&lock_);
            CloseHandle(stopEvent);
            CloseHandle(wakeEvent);
            if (unusedStream) unusedStream->Release();
            if (unusedEvents) unusedEvents->Release();
            SetDisplayStatus(kStatusUnavailable, false);
            return S_OK;
        }
        // The thread is detached here; its own COM reference keeps this object alive.
        CloseHandle(worker);
        return S_OK;
    }

    HRESULT Credential::UnAdvise()
    {
        if (!lockInitialized_) return S_OK;

        EnterCriticalSection(&lock_);
        stopping_ = true;
        HANDLE stopEvent = stopEvent_;
        if (stopEvent) SetEvent(stopEvent);
        ICredentialProviderCredentialEvents* events = events_;
        events_ = nullptr;
        IStream* eventsStream = eventsStream_;
        eventsStream_ = nullptr;
        ICredentialProviderCredentialEvents* pendingEvents = pendingEvents_;
        pendingEvents_ = nullptr;
        IStream* pendingEventsStream = pendingEventsStream_;
        pendingEventsStream_ = nullptr;
        HANDLE pendingStopEvent = pendingStopEvent_;
        pendingStopEvent_ = nullptr;
        HANDLE pendingWakeEvent = pendingWakeEvent_;
        pendingWakeEvent_ = nullptr;
        ClearPasswordLocked();
        ClearTapLocked();
        failureStatus_ = false;
        LeaveCriticalSection(&lock_);
        if (events) events->Release();
        if (eventsStream) eventsStream->Release();
        if (pendingEvents) pendingEvents->Release();
        if (pendingEventsStream) pendingEventsStream->Release();
        if (pendingStopEvent) CloseHandle(pendingStopEvent);
        if (pendingWakeEvent) CloseHandle(pendingWakeEvent);
        return S_OK;
    }

    void Credential::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario) noexcept
    {
        if (!lockInitialized_) return;
        EnterCriticalSection(&lock_);
        scenario_ = scenario;
        LeaveCriticalSection(&lock_);
    }

    void Credential::SetUserArray(ICredentialProviderUserArray* users) noexcept
    {
        if (users) users->AddRef();
        ICredentialProviderUserArray* previous = nullptr;
        if (lockInitialized_)
        {
            EnterCriticalSection(&lock_);
            previous = users_;
            users_ = users;
            LeaveCriticalSection(&lock_);
        }
        if (previous) previous->Release();
        if (!lockInitialized_ && users) users->Release();
    }

    HRESULT Credential::SetSelected(BOOL* autoLogon)
    {
        if (!autoLogon) return E_POINTER;
        *autoLogon = FALSE;
        return S_OK;
    }

    HRESULT Credential::SetDeselected()
    {
        if (lockInitialized_)
        {
            EnterCriticalSection(&lock_);
            ClearPasswordLocked();
            LeaveCriticalSection(&lock_);
        }
        return S_OK;
    }

    HRESULT Credential::GetFieldState(
        DWORD fieldId, CREDENTIAL_PROVIDER_FIELD_STATE* state,
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactiveState)
    {
        if (!state || !interactiveState) return E_POINTER;
        if (fieldId >= FieldCount) return E_INVALIDARG;

        *state = CPFS_DISPLAY_IN_SELECTED_TILE;
        *interactiveState = CPFIS_NONE;
        if (fieldId == FieldStatus)
        {
            *state = CPFS_DISPLAY_IN_BOTH;
            return S_OK;
        }
        if (fieldId == FieldPassword)
        {
            bool visible = false;
            if (lockInitialized_)
            {
                EnterCriticalSection(&lock_);
                visible = passwordVisible_;
                LeaveCriticalSection(&lock_);
            }
            if (!visible)
            {
                *state = CPFS_HIDDEN;
                *interactiveState = CPFIS_DISABLED;
            }
            return S_OK;
        }
        return S_OK;
    }

    HRESULT Credential::GetStringValue(DWORD fieldId, LPWSTR* value)
    {
        if (!value) return E_POINTER;
        *value = nullptr;
        if (fieldId != FieldStatus && fieldId != FieldPassword) return E_INVALIDARG;
        if (!lockInitialized_)
            return SHStrDupW(fieldId == FieldStatus ? kStatusUnavailable : L"", value);

        EnterCriticalSection(&lock_);
        const wchar_t* source = nullptr;
        if (fieldId == FieldStatus)
            source = statusText_.empty() ? kStatusPrompt : statusText_.c_str();
        else
            source = password_.c_str();
        const HRESULT hr = SHStrDupW(source, value);
        LeaveCriticalSection(&lock_);
        return hr;
    }

    HRESULT Credential::GetBitmapValue(DWORD, HBITMAP* bitmap)
    {
        if (!bitmap) return E_POINTER;
        *bitmap = nullptr;
        return E_NOTIMPL;
    }

    HRESULT Credential::GetCheckboxValue(DWORD, BOOL*, LPWSTR*) { return E_NOTIMPL; }

    HRESULT Credential::GetSubmitButtonValue(DWORD fieldId, DWORD* adjacentTo)
    {
        if (!adjacentTo) return E_POINTER;
        if (fieldId != FieldSubmit) return E_INVALIDARG;
        *adjacentTo = FieldPassword;
        return S_OK;
    }

    HRESULT Credential::GetComboBoxValueCount(DWORD, DWORD*, DWORD*) { return E_NOTIMPL; }
    HRESULT Credential::GetComboBoxValueAt(DWORD, DWORD, LPWSTR*) { return E_NOTIMPL; }

    HRESULT Credential::SetStringValue(DWORD fieldId, LPCWSTR value)
    {
        if (fieldId != FieldPassword) return E_INVALIDARG;
        if (!value) return E_INVALIDARG;
        if (!lockInitialized_) return S_OK;
        try
        {
            EnterCriticalSection(&lock_);
            if (passwordVisible_)
            {
                ClearPasswordLocked();
                password_.assign(value);
            }
            else
            {
                ClearPasswordLocked();
            }
            LeaveCriticalSection(&lock_);
            return S_OK;
        }
        catch (...)
        {
            LeaveCriticalSection(&lock_);
            return E_OUTOFMEMORY;
        }
    }

    HRESULT Credential::SetCheckboxValue(DWORD, BOOL) { return E_NOTIMPL; }
    HRESULT Credential::SetComboBoxSelectedValue(DWORD, DWORD) { return E_NOTIMPL; }
    HRESULT Credential::CommandLinkClicked(DWORD) { return E_NOTIMPL; }

    bool Credential::IsTapCurrentLocked(ULONGLONG now) const noexcept
    {
        return tapKnown_ && (consumed_ || (now >= tapObservedAt_ && now - tapObservedAt_ < tapTtlMs_));
    }

    void Credential::ClearTapLocked() noexcept
    {
        tapKnown_ = false;
        tapUser_.clear();
        tapNonce_.clear();
        tapTtlMs_ = 0;
        tapObservedAt_ = 0;
        consumeRequested_ = false;
        consumeInFlight_ = false;
        requestedNonce_.clear();
        consumeDone_ = false;
        consumeSucceeded_ = false;
        consumed_ = false;
        passwordVisible_ = false;
    }

    void Credential::ClearPasswordLocked() noexcept
    {
        SecureZeroPassword(password_);
        password_.clear();
    }

    void Credential::NotifyFields(const std::wstring& status, bool passwordVisible, bool) noexcept
    {
        ICredentialProviderCredentialEvents* events = nullptr;
        if (!lockInitialized_) return;
        EnterCriticalSection(&lock_);
        if (!stopping_)
            events = GetCurrentThreadId() == workerThreadId_ ? workerEvents_ : events_;
        if (events) events->AddRef();
        LeaveCriticalSection(&lock_);
        if (!events) return;

        events->SetFieldString(this, FieldStatus, status.c_str());
        events->SetFieldState(this, FieldPassword,
            passwordVisible ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN);
        events->SetFieldInteractiveState(this, FieldPassword,
            passwordVisible ? CPFIS_NONE : CPFIS_DISABLED);
        events->Release();
    }

    void Credential::SetDisplayStatus(const wchar_t* text, bool passwordVisible) noexcept
    {
        if (!lockInitialized_ || !text) return;
        std::wstring status;
        bool changed = false;
        try
        {
            EnterCriticalSection(&lock_);
            changed = statusText_ != text || passwordVisible_ != passwordVisible;
            statusText_ = text;
            passwordVisible_ = passwordVisible;
            status = statusText_;
            LeaveCriticalSection(&lock_);
        }
        catch (...)
        {
            LeaveCriticalSection(&lock_);
            return;
        }
        if (changed) NotifyFields(status, passwordVisible, true);
    }

    void Credential::ApplyStatusResult(PipeResult result) noexcept
    {
        bool changed = false;
        bool visible = false;
        std::wstring status;
        try
        {
            if (!lockInitialized_) return;
            EnterCriticalSection(&lock_);
            const std::wstring oldStatus = statusText_;
            const bool oldVisible = passwordVisible_;
            if (result.kind == PipeResultKind::Tap)
            {
                if (!tapKnown_ || tapNonce_ != result.nonce)
                {
                    ClearPasswordLocked();
                    consumeRequested_ = false;
                    consumeInFlight_ = false;
                    requestedNonce_.clear();
                    consumeDone_ = false;
                    consumeSucceeded_ = false;
                    consumed_ = false;
                    failureStatus_ = false;
                }
                tapKnown_ = true;
                tapUser_ = std::move(result.user);
                tapNonce_ = std::move(result.nonce);
                tapTtlMs_ = result.ttlMs;
                tapObservedAt_ = GetTickCount64();
                passwordVisible_ = true;
                statusText_ = kStatusAuthenticated;
            }
            else if (result.kind == PipeResultKind::NoTap)
            {
                if (consumed_ && tapKnown_)
                {
                    statusText_ = kStatusAuthenticated;
                    passwordVisible_ = true;
                }
                else
                {
                    ClearTapLocked();
                    ClearPasswordLocked();
                    if (!failureStatus_) statusText_ = kStatusPrompt;
                }
            }
            else
            {
                if (consumed_ && tapKnown_)
                {
                    statusText_ = kStatusAuthenticated;
                    passwordVisible_ = true;
                }
                else
                {
                    ClearTapLocked();
                    ClearPasswordLocked();
                    if (!failureStatus_) statusText_ = kStatusUnavailable;
                }
            }
            visible = passwordVisible_;
            status = statusText_;
            changed = oldStatus != statusText_ || oldVisible != passwordVisible_;
            LeaveCriticalSection(&lock_);
        }
        catch (...)
        {
            LeaveCriticalSection(&lock_);
            return;
        }
        if (changed) NotifyFields(status, visible, true);
    }

    void Credential::ApplyConsumeResult(const std::string& nonce, PipeResult result) noexcept
    {
        bool changed = false;
        bool visible = false;
        std::wstring status;
        try
        {
            if (!lockInitialized_) return;
            EnterCriticalSection(&lock_);
            if (tapKnown_ && tapNonce_ == nonce)
            {
                const std::wstring oldStatus = statusText_;
                const bool oldVisible = passwordVisible_;
                consumeRequested_ = false;
                consumeInFlight_ = false;
                requestedNonce_.clear();
                consumeDone_ = true;
                consumeSucceeded_ = IsConsumeAccepted(result);
                if (consumeSucceeded_)
                {
                    consumed_ = true;
                    failureStatus_ = false;
                    statusText_ = kStatusAuthenticated;
                    passwordVisible_ = true;
                }
                else
                {
                    consumed_ = false;
                    failureStatus_ = true;
                    ClearPasswordLocked();
                    ClearTapLocked();
                    statusText_ = result.kind == PipeResultKind::ServiceUnavailable
                        ? kStatusUnavailable : kStatusAuthenticationFailed;
                }
                visible = passwordVisible_;
                status = statusText_;
                changed = oldStatus != statusText_ || oldVisible != passwordVisible_;
            }
            LeaveCriticalSection(&lock_);
        }
        catch (...)
        {
            LeaveCriticalSection(&lock_);
            return;
        }
        if (changed) NotifyFields(status, visible, true);
    }

    /*
     * Worker ownership: Advise adds one credential reference before creating the thread and
     * detaches its handle. UnAdvise only marks stopping and drops the UI sink; the worker owns
     * its marshaled sink and wait handles until cleanup. WorkerEntry starts any queued advise
     * only after cleanup, then releases its reference as its final object access.
     */
    DWORD WINAPI Credential::WorkerEntry(void* context) noexcept
    {
        auto* self = static_cast<Credential*>(context);
        if (self)
        {
            self->Worker();
            self->StartPendingWorker();
            // Cleanup and queued-start member access are complete before this release.
            self->Release();
            ModuleWorkerStopped();
        }
        return 0;
    }

    void Credential::Worker() noexcept
    {
        const HRESULT comResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        IStream* marshaledEvents = nullptr;
        EnterCriticalSection(&lock_);
        marshaledEvents = eventsStream_;
        eventsStream_ = nullptr;
        workerThreadId_ = GetCurrentThreadId();
        LeaveCriticalSection(&lock_);

        ICredentialProviderCredentialEvents* workerEvents = nullptr;
        if (marshaledEvents)
        {
            if (SUCCEEDED(comResult))
            {
                const HRESULT unmarshalResult = CoGetInterfaceAndReleaseStream(marshaledEvents,
                    IID_ICredentialProviderCredentialEvents,
                    reinterpret_cast<void**>(&workerEvents));
                if (FAILED(unmarshalResult) && workerEvents)
                {
                    workerEvents->Release();
                    workerEvents = nullptr;
                }
            }
            else
            {
                marshaledEvents->Release();
            }
        }
        EnterCriticalSection(&lock_);
        workerEvents_ = workerEvents;
        LeaveCriticalSection(&lock_);
        if (!workerEvents) SetDisplayStatus(kStatusUnavailable, false);

        for (;;)
        {
            HANDLE stopEvent = nullptr;
            HANDLE wakeEvent = nullptr;
            bool stop = false;
            bool consume = false;
            std::string nonce;
            try
            {
                EnterCriticalSection(&lock_);
                stopEvent = stopEvent_;
                wakeEvent = wakeEvent_;
                stop = stopping_ || !workerRunning_ || !stopEvent;
                if (!stop && consumeRequested_)
                {
                    consume = true;
                    nonce = requestedNonce_;
                    consumeRequested_ = false;
                    consumeInFlight_ = true;
                }
                LeaveCriticalSection(&lock_);
            }
            catch (...)
            {
                LeaveCriticalSection(&lock_);
                stop = true;
            }
            if (stop) break;

            if (consume)
            {
                PipeResult consumed = authService_->Consume(nonce);
                ApplyConsumeResult(nonce, std::move(consumed));

                EnterCriticalSection(&lock_);
                stop = stopping_;
                LeaveCriticalSection(&lock_);
                if (stop) break;
            }

            PipeResult status = authService_->QueryStatus();
            ApplyStatusResult(std::move(status));

            HANDLE handles[2] = { stopEvent, wakeEvent };
            const DWORD count = wakeEvent ? 2 : 1;
            const DWORD wait = WaitForMultipleObjects(count, handles, FALSE, 500);
            if (wait == WAIT_OBJECT_0) break;
        }
        EnterCriticalSection(&lock_);
        workerEvents = workerEvents_;
        workerEvents_ = nullptr;
        workerThreadId_ = 0;
        HANDLE stopEvent = stopEvent_;
        HANDLE wakeEvent = wakeEvent_;
        IStream* remainingStream = eventsStream_;
        stopEvent_ = nullptr;
        wakeEvent_ = nullptr;
        eventsStream_ = nullptr;
        workerRunning_ = false;
        LeaveCriticalSection(&lock_);
        if (workerEvents) workerEvents->Release();
        if (remainingStream) remainingStream->Release();
        if (stopEvent) CloseHandle(stopEvent);
        if (wakeEvent) CloseHandle(wakeEvent);
        if (SUCCEEDED(comResult)) CoUninitialize();
    }

    void Credential::StartPendingWorker() noexcept
    {
        HANDLE stopEvent = nullptr;
        HANDLE wakeEvent = nullptr;
        EnterCriticalSection(&lock_);
        if (!workerRunning_ && stopping_ && pendingEvents_)
        {
            events_ = pendingEvents_;
            eventsStream_ = pendingEventsStream_;
            stopEvent_ = pendingStopEvent_;
            wakeEvent_ = pendingWakeEvent_;
            pendingEvents_ = nullptr;
            pendingEventsStream_ = nullptr;
            pendingStopEvent_ = nullptr;
            pendingWakeEvent_ = nullptr;
            stopEvent = stopEvent_;
            wakeEvent = wakeEvent_;
            stopping_ = false;
            workerRunning_ = true;
            AddRef();
            ModuleWorkerStarted();
        }
        LeaveCriticalSection(&lock_);
        if (!stopEvent) return;

        HANDLE worker = CreateThread(nullptr, 0, WorkerEntry, this, 0, nullptr);
        if (worker)
        {
            CloseHandle(worker);
            return;
        }

        ModuleWorkerStopped();
        Release();
        EnterCriticalSection(&lock_);
        ICredentialProviderCredentialEvents* unusedEvents = events_;
        IStream* unusedStream = eventsStream_;
        const bool ownsEvents = stopEvent_ == stopEvent;
        if (ownsEvents)
        {
            events_ = nullptr;
            eventsStream_ = nullptr;
            stopEvent_ = nullptr;
            wakeEvent_ = nullptr;
            workerRunning_ = false;
            stopping_ = true;
        }
        LeaveCriticalSection(&lock_);
        if (ownsEvents)
        {
            if (unusedEvents) unusedEvents->Release();
            if (unusedStream) unusedStream->Release();
            if (stopEvent) CloseHandle(stopEvent);
            if (wakeEvent) CloseHandle(wakeEvent);
        }
        SetDisplayStatus(kStatusUnavailable, false);
    }

    HRESULT Credential::SetOptionalStatus(LPWSTR* statusText,
                                           CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon,
                                           const wchar_t* text) noexcept
    {
        if (statusText) *statusText = nullptr;
        if (statusIcon)
        {
            const std::wstring_view value = text ? std::wstring_view(text) : std::wstring_view();
            const bool informational = value == kStatusPrompt || value == kStatusChecking ||
                                       value == kStatusAuthenticated || value == kStatusPasswordRequired;
            *statusIcon = informational ? CPSI_NONE : CPSI_ERROR;
        }
        if (statusText && text) SHStrDupW(text, statusText);
        return S_OK;
    }

    HRESULT Credential::GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
        LPWSTR* statusText, CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon)
    {
        if (!response || !serialization || !statusText || !statusIcon) return E_POINTER;
        *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        ZeroMemory(serialization, sizeof(*serialization));
        *statusText = nullptr;
        *statusIcon = CPSI_NONE;
        if (!lockInitialized_)
            return SetOptionalStatus(statusText, statusIcon, kStatusUnavailable);

        SecureWString password;
        std::wstring identity;
        CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario = CPUS_INVALID;
        ICredentialProviderUserArray* users = nullptr;
        std::string selectedNonce;
        bool resolvedFromUsers = false;
        bool tapExpired = false;
        bool passwordMissing = false;
        std::wstring currentStatus;
        const ULONGLONG now = GetTickCount64();

        try
        {
            EnterCriticalSection(&lock_);
            if (!IsTapCurrentLocked(now))
            {
                ClearTapLocked();
                ClearPasswordLocked();
                if (!failureStatus_) statusText_ = kStatusPrompt;
                currentStatus = statusText_;
                tapExpired = true;
            }
            else if (password_.empty())
            {
                passwordMissing = true;
            }
            else
            {
                identity = tapUser_;
                scenario = scenario_;
                selectedNonce = tapNonce_;
                users = users_;
                if (users) users->AddRef();
            }
            LeaveCriticalSection(&lock_);
        }
        catch (...)
        {
            LeaveCriticalSection(&lock_);
            if (users) users->Release();
            SetDisplayStatus(kStatusSerializationFailed, false);
            return SetOptionalStatus(statusText, statusIcon, kStatusSerializationFailed);
        }

        if (tapExpired)
        {
            NotifyFields(currentStatus, false, true);
            return SetOptionalStatus(statusText, statusIcon,
                currentStatus.empty() ? kStatusPrompt : currentStatus.c_str());
        }
        if (passwordMissing)
            return SetOptionalStatus(statusText, statusIcon, kStatusPasswordRequired);

        if (identity.empty() && scenario == CPUS_UNLOCK_WORKSTATION)
        {
            UnlockUserResult userResult = UnlockUserResult::Missing;
            try { userResult = GetUnlockUser(users, &identity); }
            catch (...) { userResult = UnlockUserResult::Missing; }
            if (userResult == UnlockUserResult::Ambiguous)
            {
                if (users) users->Release();
                SetDisplayStatus(kStatusUserAmbiguous, false);
                return SetOptionalStatus(statusText, statusIcon, kStatusUserAmbiguous);
            }
            if (userResult != UnlockUserResult::Found)
            {
                if (users) users->Release();
                SetDisplayStatus(kStatusUserMissing, false);
                return SetOptionalStatus(statusText, statusIcon, kStatusUserMissing);
            }
            resolvedFromUsers = true;
        }
        else if (identity.empty())
        {
            if (users) users->Release();
            SetDisplayStatus(kStatusUserMissing, false);
            return SetOptionalStatus(statusText, statusIcon, kStatusUserMissing);
        }

        SubmitAction action = SubmitAction::NoTap;
        bool notify = false;
        bool visible = false;
        bool readyToSerialize = false;
        const ULONGLONG submitTime = GetTickCount64();
        try
        {
            EnterCriticalSection(&lock_);
            if (!IsTapCurrentLocked(submitTime) || tapNonce_ != selectedNonce ||
                (resolvedFromUsers && users_ != users))
            {
                currentStatus = failureStatus_ && !statusText_.empty()
                    ? statusText_ : std::wstring(kStatusPrompt);
                action = SubmitAction::NoTap;
            }
            else
            {
                SubmitSnapshot snapshot;
                snapshot.tapCurrent = true;
                snapshot.passwordPresent = !password_.empty();
                snapshot.consumed = consumed_;
                snapshot.consumeDone = consumeDone_;
                snapshot.consumeSucceeded = consumeSucceeded_;
                snapshot.consumeRequested = consumeRequested_;
                snapshot.consumeInFlight = consumeInFlight_;
                snapshot.currentNonce = tapNonce_;
                snapshot.pendingNonce = requestedNonce_;
                SubmitDecision decision = DecideSubmission(snapshot);
                action = decision.action;

                switch (action)
                {
                case SubmitAction::NoTap:
                    currentStatus = kStatusPrompt;
                    break;
                case SubmitAction::PasswordRequired:
                    currentStatus = kStatusPasswordRequired;
                    break;
                case SubmitAction::RequestConsume:
                    consumeRequested_ = true;
                    consumeInFlight_ = false;
                    requestedNonce_ = std::move(decision.nonce);
                    statusText_ = kStatusChecking;
                    currentStatus = statusText_;
                    notify = true;
                    if (wakeEvent_) SetEvent(wakeEvent_);
                    break;
                case SubmitAction::WaitForConsume:
                    currentStatus = statusText_.empty() ? kStatusChecking : statusText_;
                    break;
                case SubmitAction::ConsumeFailed:
                    currentStatus = statusText_.empty()
                        ? kStatusAuthenticationFailed : statusText_;
                    break;
                case SubmitAction::Serialize:
                    if (!TakePasswordForSerialization(decision, password_, &password.value))
                    {
                        ClearPasswordLocked();
                        statusText_ = kStatusSerializationFailed;
                        currentStatus = statusText_;
                        action = SubmitAction::ConsumeFailed;
                        notify = true;
                        break;
                    }
                    scenario = scenario_;
                    ClearTapLocked();
                    statusText_ = kStatusPrompt;
                    currentStatus = statusText_;
                    readyToSerialize = true;
                    notify = true;
                    break;
                }
                visible = passwordVisible_;
            }
            LeaveCriticalSection(&lock_);
        }
        catch (...)
        {
            LeaveCriticalSection(&lock_);
            if (users) users->Release();
            SetDisplayStatus(kStatusSerializationFailed, false);
            return SetOptionalStatus(statusText, statusIcon, kStatusSerializationFailed);
        }
        if (users) users->Release();

        if (!readyToSerialize)
        {
            if (notify) NotifyFields(currentStatus, visible, true);
            switch (action)
            {
            case SubmitAction::PasswordRequired:
                return SetOptionalStatus(statusText, statusIcon, kStatusPasswordRequired);
            case SubmitAction::ConsumeFailed:
                return SetOptionalStatus(statusText, statusIcon,
                    currentStatus.empty() ? kStatusAuthenticationFailed : currentStatus.c_str());
            case SubmitAction::WaitForConsume:
                return SetOptionalStatus(statusText, statusIcon,
                    currentStatus.empty() ? kStatusChecking : currentStatus.c_str());
            case SubmitAction::RequestConsume:
                // GetSerialization cannot resume asynchronously after the worker's consume call.
                // The first press queues consume and returns unfinished; the next press serializes.
                return SetOptionalStatus(statusText, statusIcon, kStatusChecking);
            case SubmitAction::NoTap:
                return SetOptionalStatus(statusText, statusIcon,
                    currentStatus.empty() ? kStatusPrompt : currentStatus.c_str());
            case SubmitAction::Serialize:
                break;
            }
        }

        std::wstring domain;
        std::wstring user;
        bool splitOk = false;
        try { splitOk = SplitIdentity(identity, &domain, &user); }
        catch (...) { splitOk = false; }
        if (!splitOk)
        {
            SetDisplayStatus(kStatusUserMissing, false);
            return SetOptionalStatus(statusText, statusIcon, kStatusUserMissing);
        }

        BYTE* buffer = nullptr;
        ULONG bufferSize = 0;
        const KerbScenario kerbScenario = scenario == CPUS_UNLOCK_WORKSTATION
            ? KerbScenario::Unlock : KerbScenario::Logon;
        const HRESULT packResult = PackKerbLogon(domain, user, password.value,
                                                   kerbScenario, &buffer, &bufferSize);
        SecureZeroPassword(password.value);
        if (FAILED(packResult))
        {
            SetDisplayStatus(kStatusSerializationFailed, false);
            return SetOptionalStatus(statusText, statusIcon, kStatusSerializationFailed);
        }

        ULONG packageId = 0;
        const HRESULT packageResult = LookupNegotiatePackage(&packageId);
        if (FAILED(packageResult))
        {
            SecureFreeKerbBuffer(buffer, bufferSize);
            SetDisplayStatus(kStatusSerializationFailed, false);
            return SetOptionalStatus(statusText, statusIcon, kStatusSerializationFailed);
        }

        serialization->ulAuthenticationPackage = packageId;
        serialization->cbSerialization = bufferSize;
        serialization->rgbSerialization = buffer;
        serialization->clsidCredentialProvider = CLSID_NfcCredentialProvider;
        *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
        *statusIcon = CPSI_NONE;
        return S_OK;
    }

    HRESULT Credential::ReportResult(NTSTATUS, NTSTATUS, LPWSTR* statusText,
                                      CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon)
    {
        if (statusText) *statusText = nullptr;
        if (statusIcon) *statusIcon = CPSI_NONE;
        if (lockInitialized_)
        {
            EnterCriticalSection(&lock_);
            ClearPasswordLocked();
            LeaveCriticalSection(&lock_);
        }
        return S_OK;
    }

    HRESULT Credential::Connect(IQueryContinueWithStatus*)
    {
        return S_OK;
    }

    HRESULT Credential::Disconnect()
    {
        if (lockInitialized_)
        {
            EnterCriticalSection(&lock_);
            ClearPasswordLocked();
            LeaveCriticalSection(&lock_);
        }
        return S_OK;
    }
}
