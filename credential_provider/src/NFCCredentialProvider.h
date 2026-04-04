/*
 * NFC Credential Provider for Windows
 * ====================================
 *
 * Integrates iPhone Express Card (Suica) authentication
 * directly into Windows login screen.
 *
 * Author: Generated with Claude Code
 * License: MIT
 */

#pragma once

#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <string>

// GUID for our credential provider
// {A0B1C2D3-E4F5-6789-ABCD-EF0123456789}
DEFINE_GUID(CLSID_NFCCredentialProvider,
    0xa0b1c2d3, 0xe4f5, 0x6789, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89);

// Signal file path for NFC daemon communication
#define NFC_SIGNAL_FILE L"C:\\Users\\suger.G-GEAR\\nfc-windows-auth\\.nfc_auth_signal"
#define NFC_CRED_FILE   L"C:\\Users\\suger.G-GEAR\\nfc-windows-auth\\.credentials.dpapi"

// Forward declarations
class CNFCCredential;
class CNFCCredentialProvider;

// Helper functions
HRESULT ReadCredentialFromFile(std::wstring& username, std::wstring& password);
BOOL CheckNFCSignal();
void ClearNFCSignal();

//
// CNFCCredentialProvider - The main provider class
//
class CNFCCredentialProvider : public ICredentialProvider,
                                public ICredentialProviderSetUserArray
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc);

    // ICredentialProviderSetUserArray
    IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray* users);

    CNFCCredentialProvider();

private:
    virtual ~CNFCCredentialProvider();

    LONG m_cRef;
    CNFCCredential* m_pCredential;
    ICredentialProviderEvents* m_pEvents;
    UINT_PTR m_upAdviseContext;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;
    ICredentialProviderUserArray* m_pUserArray;
    HANDLE m_hCheckThread;
    BOOL m_bThreadRunning;

    static DWORD WINAPI CheckNFCThread(LPVOID lpParam);
    void StartNFCCheck();
    void StopNFCCheck();
};

//
// CNFCCredential - Individual credential tile
//
class CNFCCredential : public ICredentialProviderCredential2,
                       public IConnectableCredentialProviderCredential
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                  CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, LPWSTR* ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, LPWSTR* ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, LPWSTR* ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, LPCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                     CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                     LPWSTR* ppwszOptionalStatusText,
                                     CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
                                 LPWSTR* ppwszOptionalStatusText,
                                 CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    // ICredentialProviderCredential2
    IFACEMETHODIMP GetUserSid(LPWSTR* ppszSid);

    // IConnectableCredentialProviderCredential
    IFACEMETHODIMP Connect(IQueryContinueWithStatus* pqcws);
    IFACEMETHODIMP Disconnect();

    CNFCCredential();
    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                       ICredentialProviderUser* pUser);

    void SetAuthenticated(BOOL bAuth);
    BOOL IsAuthenticated() const { return m_bAuthenticated; }

private:
    virtual ~CNFCCredential();

    LONG m_cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;
    ICredentialProviderCredentialEvents2* m_pEvents;
    ICredentialProviderUser* m_pUser;

    BOOL m_bAuthenticated;
    std::wstring m_wsUsername;
    std::wstring m_wsPassword;
    std::wstring m_wsUserSid;
};

// Field IDs
enum FIELD_ID {
    FI_ICON = 0,
    FI_LABEL = 1,
    FI_STATUS = 2,
    FI_SUBMIT = 3,
    FI_NUM_FIELDS = 4
};

// Class factory
class CNFCCredentialProviderFactory : public IClassFactory
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);

    // IClassFactory
    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv);
    IFACEMETHODIMP LockServer(BOOL bLock);

    CNFCCredentialProviderFactory();

private:
    virtual ~CNFCCredentialProviderFactory();
    LONG m_cRef;
};
