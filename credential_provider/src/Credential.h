#pragma once

#include <windows.h>
#include <objidl.h>
#include <credentialprovider.h>
#include <string>

namespace NfcAuth
{
    class IAuthService;

    class Credential final : public IConnectableCredentialProviderCredential
    {
    public:
        explicit Credential(IAuthService* authService = nullptr) noexcept;

        IFACEMETHODIMP QueryInterface(REFIID riid, void** object) override;
        IFACEMETHODIMP_(ULONG) AddRef() override;
        IFACEMETHODIMP_(ULONG) Release() override;

        IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* events) override;
        IFACEMETHODIMP UnAdvise() override;
        IFACEMETHODIMP SetSelected(BOOL* autoLogon) override;
        IFACEMETHODIMP SetDeselected() override;
        IFACEMETHODIMP GetFieldState(
            DWORD fieldId, CREDENTIAL_PROVIDER_FIELD_STATE* state,
            CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactiveState) override;
        IFACEMETHODIMP GetStringValue(DWORD fieldId, LPWSTR* value) override;
        IFACEMETHODIMP GetBitmapValue(DWORD fieldId, HBITMAP* bitmap) override;
        IFACEMETHODIMP GetCheckboxValue(DWORD fieldId, BOOL* checked, LPWSTR* label) override;
        IFACEMETHODIMP GetSubmitButtonValue(DWORD fieldId, DWORD* adjacentTo) override;
        IFACEMETHODIMP GetComboBoxValueCount(DWORD fieldId, DWORD* count,
                                             DWORD* selectedItem) override;
        IFACEMETHODIMP GetComboBoxValueAt(DWORD fieldId, DWORD item, LPWSTR* value) override;
        IFACEMETHODIMP SetStringValue(DWORD fieldId, LPCWSTR value) override;
        IFACEMETHODIMP SetCheckboxValue(DWORD fieldId, BOOL checked) override;
        IFACEMETHODIMP SetComboBoxSelectedValue(DWORD fieldId, DWORD selectedItem) override;
        IFACEMETHODIMP CommandLinkClicked(DWORD fieldId) override;
        IFACEMETHODIMP GetSerialization(
            CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
            CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
            LPWSTR* statusText, CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;
        IFACEMETHODIMP ReportResult(NTSTATUS status, NTSTATUS subStatus,
                                    LPWSTR* statusText,
                                    CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;
        IFACEMETHODIMP Connect(IQueryContinueWithStatus* query) override;
        IFACEMETHODIMP Disconnect() override;

        void SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario) noexcept;
        void SetUserArray(ICredentialProviderUserArray* users) noexcept;

    private:
        ~Credential() noexcept;
        static DWORD WINAPI WorkerEntry(void* context) noexcept;
        void Worker() noexcept;
        void StartPendingWorker() noexcept;
        void ApplyStatusResult(struct PipeResult result) noexcept;
        void ApplyConsumeResult(const std::string& nonce, struct PipeResult result) noexcept;
        void SetDisplayStatus(const wchar_t* status, bool passwordVisible) noexcept;
        void NotifyFields(const std::wstring& status, bool passwordVisible,
                          bool changed) noexcept;
        bool IsTapCurrentLocked(ULONGLONG now) const noexcept;
        void ClearTapLocked() noexcept;
        void ClearPasswordLocked() noexcept;
        HRESULT SetOptionalStatus(LPWSTR* statusText,
                                  CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon,
                                  const wchar_t* text) noexcept;

        LONG refCount_;
        IAuthService* authService_;
        CRITICAL_SECTION lock_;
        bool lockInitialized_;
        CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario_;
        ICredentialProviderUserArray* users_;
        ICredentialProviderCredentialEvents* events_;
        IStream* eventsStream_;
        ICredentialProviderCredentialEvents* workerEvents_;
        ICredentialProviderCredentialEvents* pendingEvents_;
        IStream* pendingEventsStream_;
        DWORD workerThreadId_;
        HANDLE stopEvent_;
        HANDLE wakeEvent_;
        HANDLE pendingStopEvent_;
        HANDLE pendingWakeEvent_;
        bool stopping_;
        bool workerRunning_;
        bool tapKnown_;
        std::wstring tapUser_;
        std::string tapNonce_;
        DWORD tapTtlMs_;
        ULONGLONG tapObservedAt_;
        bool consumeRequested_;
        bool consumeInFlight_;
        std::string requestedNonce_;
        bool consumeDone_;
        bool consumeSucceeded_;
        bool consumed_;
        bool failureStatus_;
        std::wstring password_;
        std::wstring statusText_;
        bool passwordVisible_;
    };
}
