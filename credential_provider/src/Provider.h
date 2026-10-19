#pragma once

#include <windows.h>
#include <credentialprovider.h>

namespace NfcAuth
{
    extern const CLSID CLSID_NfcCredentialProvider;

    class Credential;

    class Provider final : public ICredentialProvider,
                           public ICredentialProviderSetUserArray
    {
    public:
        Provider() noexcept;

        IFACEMETHODIMP QueryInterface(REFIID riid, void** object) override;
        IFACEMETHODIMP_(ULONG) AddRef() override;
        IFACEMETHODIMP_(ULONG) Release() override;

        IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,
                                        DWORD flags) override;
        IFACEMETHODIMP SetSerialization(
            const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization) override;
        IFACEMETHODIMP Advise(ICredentialProviderEvents* events, UINT_PTR adviseContext) override;
        IFACEMETHODIMP UnAdvise() override;
        IFACEMETHODIMP GetFieldDescriptorCount(DWORD* count) override;
        IFACEMETHODIMP GetFieldDescriptorAt(
            DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) override;
        IFACEMETHODIMP GetCredentialCount(DWORD* count, DWORD* defaultIndex,
                                          BOOL* autoLogon) override;
        IFACEMETHODIMP GetCredentialAt(
            DWORD index, ICredentialProviderCredential** credential) override;
        IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray* users) override;

    private:
        ~Provider() noexcept;
        HRESULT EnsureCredential() noexcept;

        LONG refCount_;
        CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_;
        ICredentialProviderEvents* events_;
        UINT_PTR adviseContext_;
        ICredentialProviderUserArray* users_;
        Credential* credential_;
    };
}
