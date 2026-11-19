#include "Provider.h"

#include "Credential.h"
#include "Module.h"
#include "Strings.h"

#include <shlwapi.h>
#include <new>

namespace NfcAuth
{
    namespace
    {
        // credentialprovider.h only declares these EXTERN_C, so define them here.
        // A tile image tagged with the logo GUID and a large text tagged with the
        // label GUID are what LogonUI shows in the "sign-in options" row.
        // {2D837775-F6CD-464E-A745-482FD0B47493}
        const GUID kFieldLogo =
            { 0x2d837775, 0xf6cd, 0x464e, { 0xa7, 0x45, 0x48, 0x2f, 0xd0, 0xb4, 0x74, 0x93 } };
        // {286BBFF3-BAD4-438F-B007-79B7267C3D48}
        const GUID kFieldLabel =
            { 0x286bbff3, 0xbad4, 0x438f, { 0xb0, 0x07, 0x79, 0xb7, 0x26, 0x7c, 0x3d, 0x48 } };

        const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR kFieldDescriptors[FieldCount] =
        {
            { FieldTileImage, CPFT_TILE_IMAGE, const_cast<PWSTR>(L""), kFieldLogo },
            { FieldLabel, CPFT_LARGE_TEXT, const_cast<PWSTR>(kTileLabel), kFieldLabel },
            { FieldStatus, CPFT_SMALL_TEXT, const_cast<PWSTR>(L""), GUID_NULL },
            { FieldPassword, CPFT_PASSWORD_TEXT, const_cast<PWSTR>(kPasswordFieldLabel), GUID_NULL },
            { FieldSubmit, CPFT_SUBMIT_BUTTON, const_cast<PWSTR>(kSubmitFieldLabel), GUID_NULL }
        };
    }

    Provider::Provider() noexcept
        : refCount_(1), scenario_(CPUS_INVALID), events_(nullptr), adviseContext_(0),
          users_(nullptr), credential_(nullptr)
    {
        ModuleObjectCreated();
    }

    Provider::~Provider() noexcept
    {
        if (credential_)
        {
            // Drop the back-pointer before the final release so a worker that is
            // still winding down cannot call into a destroyed provider.
            credential_->SetOwner(nullptr);
            credential_->Release();
        }
        if (users_) users_->Release();
        if (events_) events_->Release();
        ModuleObjectDestroyed();
    }

    HRESULT Provider::QueryInterface(REFIID riid, void** object)
    {
        if (!object) return E_POINTER;
        *object = nullptr;
        if (riid == IID_IUnknown || riid == IID_ICredentialProvider)
            *object = static_cast<ICredentialProvider*>(this);
        else if (riid == IID_ICredentialProviderSetUserArray)
            *object = static_cast<ICredentialProviderSetUserArray*>(this);
        else
            return E_NOINTERFACE;
        AddRef();
        return S_OK;
    }

    ULONG Provider::AddRef()
    {
        return static_cast<ULONG>(InterlockedIncrement(&refCount_));
    }

    ULONG Provider::Release()
    {
        const LONG refs = InterlockedDecrement(&refCount_);
        if (refs == 0) delete this;
        return static_cast<ULONG>(refs);
    }

    HRESULT Provider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD)
    {
        if (scenario != CPUS_LOGON && scenario != CPUS_UNLOCK_WORKSTATION) return E_NOTIMPL;
        scenario_ = scenario;
        if (credential_) credential_->SetUsageScenario(scenario);
        return S_OK;
    }

    HRESULT Provider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*)
    {
        return E_NOTIMPL;
    }

    HRESULT Provider::Advise(ICredentialProviderEvents* events, UINT_PTR adviseContext)
    {
        if (!events) return E_INVALIDARG;
        events->AddRef();
        if (events_) events_->Release();
        events_ = events;
        adviseContext_ = adviseContext;
        return S_OK;
    }

    HRESULT Provider::UnAdvise()
    {
        if (events_)
        {
            events_->Release();
            events_ = nullptr;
        }
        adviseContext_ = 0;
        return S_OK;
    }

    HRESULT Provider::GetFieldDescriptorCount(DWORD* count)
    {
        if (!count) return E_POINTER;
        *count = FieldCount;
        return S_OK;
    }

    HRESULT Provider::GetFieldDescriptorAt(DWORD index,
                                           CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor)
    {
        if (!descriptor) return E_POINTER;
        *descriptor = nullptr;
        if (index >= FieldCount) return E_INVALIDARG;

        auto* copy = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
            CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
        if (!copy) return E_OUTOFMEMORY;
        *copy = kFieldDescriptors[index];
        const HRESULT hr = SHStrDupW(kFieldDescriptors[index].pszLabel, &copy->pszLabel);
        if (FAILED(hr))
        {
            CoTaskMemFree(copy);
            return hr;
        }
        *descriptor = copy;
        return S_OK;
    }

    HRESULT Provider::MarshalEventsForWorker(IStream** stream, UINT_PTR* context) noexcept
    {
        if (!stream || !context) return E_POINTER;
        *stream = nullptr;
        *context = 0;
        if (!events_) return E_NOT_VALID_STATE;

        IStream* marshaled = nullptr;
        const HRESULT hr = CoMarshalInterThreadInterfaceInStream(
            IID_ICredentialProviderEvents, events_, &marshaled);
        if (FAILED(hr))
        {
            if (marshaled) marshaled->Release();
            return hr;
        }
        *stream = marshaled;
        *context = adviseContext_;
        return S_OK;
    }

    HRESULT Provider::GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogon)
    {
        if (!count || !defaultIndex || !autoLogon) return E_POINTER;
        *count = 1;
        *defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *autoLogon = FALSE;

        // A tap only submits by itself once a stored credential has been matched
        // to it. Without one the tile stays interactive and asks for a password.
        if (credential_ && credential_->WantsAutoLogon())
        {
            *defaultIndex = 0;
            *autoLogon = TRUE;
        }
        return S_OK;
    }

    HRESULT Provider::EnsureCredential() noexcept
    {
        if (credential_) return S_OK;
        Credential* credential = new (std::nothrow) Credential();
        if (!credential) return E_OUTOFMEMORY;
        credential->SetOwner(this);
        credential->SetUsageScenario(scenario_);
        credential->SetUserArray(users_);
        credential_ = credential;
        return S_OK;
    }

    HRESULT Provider::GetCredentialAt(DWORD index, ICredentialProviderCredential** credential)
    {
        if (!credential) return E_POINTER;
        *credential = nullptr;
        if (index != 0) return E_INVALIDARG;
        HRESULT hr = EnsureCredential();
        if (FAILED(hr)) return hr;
        return credential_->QueryInterface(IID_ICredentialProviderCredential,
                                           reinterpret_cast<void**>(credential));
    }

    HRESULT Provider::SetUserArray(ICredentialProviderUserArray* users)
    {
        if (!users) return E_INVALIDARG;
        users->AddRef();
        ICredentialProviderUserArray* previous = users_;
        users_ = users;
        if (credential_) credential_->SetUserArray(users);
        if (previous) previous->Release();
        return S_OK;
    }
}
