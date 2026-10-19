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
        const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR kFieldDescriptors[FieldCount] =
        {
            { FieldStatus, CPFT_LARGE_TEXT, const_cast<PWSTR>(L""), GUID_NULL },
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
        if (credential_) credential_->Release();
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

    HRESULT Provider::GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogon)
    {
        if (!count || !defaultIndex || !autoLogon) return E_POINTER;
        *count = 1;
        *defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *autoLogon = FALSE;
        return S_OK;
    }

    HRESULT Provider::EnsureCredential() noexcept
    {
        if (credential_) return S_OK;
        Credential* credential = new (std::nothrow) Credential();
        if (!credential) return E_OUTOFMEMORY;
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
