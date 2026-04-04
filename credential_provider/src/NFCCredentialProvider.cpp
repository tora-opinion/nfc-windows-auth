/*
 * NFC Credential Provider Implementation
 */

#include "NFCCredentialProvider.h"
#include <wincred.h>
#include <shlwapi.h>
#include <strsafe.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "crypt32.lib")

// Global DLL reference count
static LONG g_cRef = 0;
static HINSTANCE g_hInstance = NULL;

// Field descriptors
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgFieldDescriptors[] = {
    { FI_ICON,   CPFT_TILE_IMAGE,    L"Icon",   CPFG_CREDENTIAL_PROVIDER_LOGO },
    { FI_LABEL,  CPFT_LARGE_TEXT,    L"NFC Login", 0 },
    { FI_STATUS, CPFT_SMALL_TEXT,    L"Place iPhone on reader", 0 },
    { FI_SUBMIT, CPFT_SUBMIT_BUTTON, L"Submit", 0 },
};

//
// Helper: Read encrypted credential from DPAPI file
//
HRESULT ReadCredentialFromFile(std::wstring& username, std::wstring& password) {
    HANDLE hFile = CreateFileW(NFC_CRED_FILE, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return E_FAIL;
    }

    DWORD dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0 || dwSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return E_FAIL;
    }

    BYTE* pBuffer = new BYTE[dwSize];
    DWORD dwRead;
    if (!ReadFile(hFile, pBuffer, dwSize, &dwRead, NULL)) {
        delete[] pBuffer;
        CloseHandle(hFile);
        return E_FAIL;
    }
    CloseHandle(hFile);

    // Decrypt with DPAPI
    DATA_BLOB blobIn = { dwRead, pBuffer };
    DATA_BLOB blobOut = { 0 };

    if (!CryptUnprotectData(&blobIn, NULL, NULL, NULL, NULL, 0, &blobOut)) {
        delete[] pBuffer;
        return E_FAIL;
    }

    delete[] pBuffer;

    // Convert to string
    password = std::wstring((wchar_t*)blobOut.pbData, blobOut.cbData / sizeof(wchar_t));
    LocalFree(blobOut.pbData);

    // Get current username
    WCHAR wszUsername[256];
    DWORD dwLen = 256;
    if (GetUserNameW(wszUsername, &dwLen)) {
        username = wszUsername;
    }

    return S_OK;
}

//
// Helper: Check if NFC signal file exists
//
BOOL CheckNFCSignal() {
    return PathFileExistsW(NFC_SIGNAL_FILE);
}

//
// Helper: Clear NFC signal
//
void ClearNFCSignal() {
    DeleteFileW(NFC_SIGNAL_FILE);
}

//
// CNFCCredentialProvider Implementation
//

CNFCCredentialProvider::CNFCCredentialProvider()
    : m_cRef(1)
    , m_pCredential(NULL)
    , m_pEvents(NULL)
    , m_upAdviseContext(0)
    , m_cpus(CPUS_INVALID)
    , m_pUserArray(NULL)
    , m_hCheckThread(NULL)
    , m_bThreadRunning(FALSE)
{
    InterlockedIncrement(&g_cRef);
}

CNFCCredentialProvider::~CNFCCredentialProvider() {
    StopNFCCheck();
    if (m_pCredential) {
        m_pCredential->Release();
    }
    if (m_pUserArray) {
        m_pUserArray->Release();
    }
    InterlockedDecrement(&g_cRef);
}

ULONG CNFCCredentialProvider::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

ULONG CNFCCredentialProvider::Release() {
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0) {
        delete this;
    }
    return cRef;
}

HRESULT CNFCCredentialProvider::QueryInterface(REFIID riid, void** ppv) {
    static const QITAB qit[] = {
        QITABENT(CNFCCredentialProvider, ICredentialProvider),
        QITABENT(CNFCCredentialProvider, ICredentialProviderSetUserArray),
        { 0 },
    };
    return QISearch(this, qit, riid, ppv);
}

HRESULT CNFCCredentialProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags)
{
    m_cpus = cpus;

    // We only support logon and unlock
    switch (cpus) {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        return S_OK;
    default:
        return E_NOTIMPL;
    }
}

HRESULT CNFCCredentialProvider::SetSerialization(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    return E_NOTIMPL;
}

HRESULT CNFCCredentialProvider::Advise(
    ICredentialProviderEvents* pcpe,
    UINT_PTR upAdviseContext)
{
    if (m_pEvents) {
        m_pEvents->Release();
    }
    m_pEvents = pcpe;
    m_pEvents->AddRef();
    m_upAdviseContext = upAdviseContext;

    // Start checking for NFC authentication
    StartNFCCheck();

    return S_OK;
}

HRESULT CNFCCredentialProvider::UnAdvise() {
    StopNFCCheck();
    if (m_pEvents) {
        m_pEvents->Release();
        m_pEvents = NULL;
    }
    return S_OK;
}

HRESULT CNFCCredentialProvider::GetFieldDescriptorCount(DWORD* pdwCount) {
    *pdwCount = FI_NUM_FIELDS;
    return S_OK;
}

HRESULT CNFCCredentialProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    if (dwIndex >= FI_NUM_FIELDS) {
        return E_INVALIDARG;
    }

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pfd =
        (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));

    if (!pfd) {
        return E_OUTOFMEMORY;
    }

    *pfd = s_rgFieldDescriptors[dwIndex];

    if (s_rgFieldDescriptors[dwIndex].pszLabel) {
        SHStrDupW(s_rgFieldDescriptors[dwIndex].pszLabel, &pfd->pszLabel);
    }

    *ppcpfd = pfd;
    return S_OK;
}

HRESULT CNFCCredentialProvider::GetCredentialCount(
    DWORD* pdwCount,
    DWORD* pdwDefault,
    BOOL* pbAutoLogonWithDefault)
{
    *pdwCount = 1;
    *pdwDefault = 0;

    // Auto-logon if NFC authenticated
    if (m_pCredential && m_pCredential->IsAuthenticated()) {
        *pbAutoLogonWithDefault = TRUE;
    } else {
        *pbAutoLogonWithDefault = FALSE;
    }

    return S_OK;
}

HRESULT CNFCCredentialProvider::GetCredentialAt(
    DWORD dwIndex,
    ICredentialProviderCredential** ppcpc)
{
    if (dwIndex != 0) {
        return E_INVALIDARG;
    }

    if (!m_pCredential) {
        m_pCredential = new CNFCCredential();
        if (!m_pCredential) {
            return E_OUTOFMEMORY;
        }

        ICredentialProviderUser* pUser = NULL;
        if (m_pUserArray) {
            DWORD dwCount;
            m_pUserArray->GetCount(&dwCount);
            if (dwCount > 0) {
                m_pUserArray->GetAt(0, &pUser);
            }
        }

        m_pCredential->Initialize(m_cpus, pUser);
        if (pUser) {
            pUser->Release();
        }
    }

    m_pCredential->AddRef();
    *ppcpc = m_pCredential;
    return S_OK;
}

HRESULT CNFCCredentialProvider::SetUserArray(ICredentialProviderUserArray* users) {
    if (m_pUserArray) {
        m_pUserArray->Release();
    }
    m_pUserArray = users;
    m_pUserArray->AddRef();
    return S_OK;
}

DWORD WINAPI CNFCCredentialProvider::CheckNFCThread(LPVOID lpParam) {
    CNFCCredentialProvider* pThis = (CNFCCredentialProvider*)lpParam;

    while (pThis->m_bThreadRunning) {
        if (CheckNFCSignal()) {
            ClearNFCSignal();

            if (pThis->m_pCredential) {
                pThis->m_pCredential->SetAuthenticated(TRUE);
            }

            if (pThis->m_pEvents) {
                pThis->m_pEvents->CredentialsChanged(pThis->m_upAdviseContext);
            }
        }
        Sleep(200);  // Check every 200ms
    }

    return 0;
}

void CNFCCredentialProvider::StartNFCCheck() {
    if (!m_bThreadRunning) {
        m_bThreadRunning = TRUE;
        m_hCheckThread = CreateThread(NULL, 0, CheckNFCThread, this, 0, NULL);
    }
}

void CNFCCredentialProvider::StopNFCCheck() {
    if (m_bThreadRunning) {
        m_bThreadRunning = FALSE;
        if (m_hCheckThread) {
            WaitForSingleObject(m_hCheckThread, 1000);
            CloseHandle(m_hCheckThread);
            m_hCheckThread = NULL;
        }
    }
}

//
// CNFCCredential Implementation
//

CNFCCredential::CNFCCredential()
    : m_cRef(1)
    , m_cpus(CPUS_INVALID)
    , m_pEvents(NULL)
    , m_pUser(NULL)
    , m_bAuthenticated(FALSE)
{
    InterlockedIncrement(&g_cRef);
}

CNFCCredential::~CNFCCredential() {
    if (m_pEvents) {
        m_pEvents->Release();
    }
    if (m_pUser) {
        m_pUser->Release();
    }
    InterlockedDecrement(&g_cRef);
}

ULONG CNFCCredential::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

ULONG CNFCCredential::Release() {
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0) {
        delete this;
    }
    return cRef;
}

HRESULT CNFCCredential::QueryInterface(REFIID riid, void** ppv) {
    static const QITAB qit[] = {
        QITABENT(CNFCCredential, ICredentialProviderCredential),
        QITABENT(CNFCCredential, ICredentialProviderCredential2),
        QITABENT(CNFCCredential, IConnectableCredentialProviderCredential),
        { 0 },
    };
    return QISearch(this, qit, riid, ppv);
}

HRESULT CNFCCredential::Initialize(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    ICredentialProviderUser* pUser)
{
    m_cpus = cpus;

    if (pUser) {
        m_pUser = pUser;
        m_pUser->AddRef();

        LPWSTR pwszSid;
        if (SUCCEEDED(pUser->GetSid(&pwszSid))) {
            m_wsUserSid = pwszSid;
            CoTaskMemFree(pwszSid);
        }
    }

    return S_OK;
}

HRESULT CNFCCredential::Advise(ICredentialProviderCredentialEvents* pcpce) {
    if (m_pEvents) {
        m_pEvents->Release();
    }
    pcpce->QueryInterface(IID_PPV_ARGS(&m_pEvents));
    return S_OK;
}

HRESULT CNFCCredential::UnAdvise() {
    if (m_pEvents) {
        m_pEvents->Release();
        m_pEvents = NULL;
    }
    return S_OK;
}

HRESULT CNFCCredential::SetSelected(BOOL* pbAutoLogon) {
    *pbAutoLogon = m_bAuthenticated;
    return S_OK;
}

HRESULT CNFCCredential::SetDeselected() {
    return S_OK;
}

HRESULT CNFCCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
    *pcpfis = CPFIS_NONE;

    if (dwFieldID == FI_ICON) {
        *pcpfs = CPFS_DISPLAY_IN_BOTH;
    } else if (dwFieldID == FI_SUBMIT) {
        *pcpfs = CPFS_HIDDEN;
    }

    return S_OK;
}

HRESULT CNFCCredential::GetStringValue(DWORD dwFieldID, LPWSTR* ppwsz) {
    switch (dwFieldID) {
    case FI_LABEL:
        return SHStrDupW(L"NFC Login", ppwsz);
    case FI_STATUS:
        if (m_bAuthenticated) {
            return SHStrDupW(L"Authenticated - Logging in...", ppwsz);
        } else {
            return SHStrDupW(L"Place iPhone on reader", ppwsz);
        }
    default:
        return SHStrDupW(L"", ppwsz);
    }
}

HRESULT CNFCCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp) {
    // Use default icon
    *phbmp = NULL;
    return E_NOTIMPL;
}

HRESULT CNFCCredential::GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, LPWSTR* ppwszLabel) {
    return E_NOTIMPL;
}

HRESULT CNFCCredential::GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem) {
    return E_NOTIMPL;
}

HRESULT CNFCCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, LPWSTR* ppwszItem) {
    return E_NOTIMPL;
}

HRESULT CNFCCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo) {
    *pdwAdjacentTo = FI_STATUS;
    return S_OK;
}

HRESULT CNFCCredential::SetStringValue(DWORD dwFieldID, LPCWSTR pwz) {
    return S_OK;
}

HRESULT CNFCCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked) {
    return E_NOTIMPL;
}

HRESULT CNFCCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem) {
    return E_NOTIMPL;
}

HRESULT CNFCCredential::CommandLinkClicked(DWORD dwFieldID) {
    return E_NOTIMPL;
}

HRESULT CNFCCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    if (!m_bAuthenticated) {
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    // Read credential from file
    std::wstring username, password;
    if (FAILED(ReadCredentialFromFile(username, password))) {
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        *ppwszOptionalStatusText = NULL;
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        return E_FAIL;
    }

    // Build KERB_INTERACTIVE_UNLOCK_LOGON structure
    WCHAR wszDomain[256] = { 0 };
    DWORD dwSize = 256;
    GetComputerNameW(wszDomain, &dwSize);

    // Calculate sizes
    DWORD cbUsername = (DWORD)((username.length() + 1) * sizeof(WCHAR));
    DWORD cbPassword = (DWORD)((password.length() + 1) * sizeof(WCHAR));
    DWORD cbDomain = (DWORD)((wcslen(wszDomain) + 1) * sizeof(WCHAR));
    DWORD cbSize = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + cbUsername + cbPassword + cbDomain;

    BYTE* pBlob = (BYTE*)CoTaskMemAlloc(cbSize);
    if (!pBlob) {
        return E_OUTOFMEMORY;
    }
    ZeroMemory(pBlob, cbSize);

    KERB_INTERACTIVE_UNLOCK_LOGON* pLogon = (KERB_INTERACTIVE_UNLOCK_LOGON*)pBlob;
    KERB_INTERACTIVE_LOGON* pKIL = &pLogon->Logon;

    pKIL->MessageType = KerbInteractiveLogon;

    // Set strings
    BYTE* pStrings = pBlob + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);

    pKIL->LogonDomainName.Buffer = (PWSTR)pStrings;
    pKIL->LogonDomainName.Length = (USHORT)(cbDomain - sizeof(WCHAR));
    pKIL->LogonDomainName.MaximumLength = (USHORT)cbDomain;
    memcpy(pStrings, wszDomain, cbDomain);
    pStrings += cbDomain;

    pKIL->UserName.Buffer = (PWSTR)pStrings;
    pKIL->UserName.Length = (USHORT)(cbUsername - sizeof(WCHAR));
    pKIL->UserName.MaximumLength = (USHORT)cbUsername;
    memcpy(pStrings, username.c_str(), cbUsername);
    pStrings += cbUsername;

    pKIL->Password.Buffer = (PWSTR)pStrings;
    pKIL->Password.Length = (USHORT)(cbPassword - sizeof(WCHAR));
    pKIL->Password.MaximumLength = (USHORT)cbPassword;
    memcpy(pStrings, password.c_str(), cbPassword);

    // Fill credential serialization
    ULONG ulAuthPackage;
    HANDLE hLsa;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status))) {
        LSA_STRING lsaszKerberos = { 8, 9, (PCHAR)"Kerberos" };
        status = LsaLookupAuthenticationPackage(hLsa, &lsaszKerberos, &ulAuthPackage);
        LsaDeregisterLogonProcess(hLsa);
    }

    pcpcs->ulAuthenticationPackage = ulAuthPackage;
    pcpcs->cbSerialization = cbSize;
    pcpcs->rgbSerialization = pBlob;
    pcpcs->clsidCredentialProvider = CLSID_NFCCredentialProvider;

    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;

    return S_OK;
}

HRESULT CNFCCredential::ReportResult(
    NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = NULL;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    if (SUCCEEDED(HRESULT_FROM_NT(ntsStatus))) {
        // Clear authenticated state after successful login
        m_bAuthenticated = FALSE;
    }

    return S_OK;
}

HRESULT CNFCCredential::GetUserSid(LPWSTR* ppszSid) {
    if (!m_wsUserSid.empty()) {
        return SHStrDupW(m_wsUserSid.c_str(), ppszSid);
    }
    *ppszSid = NULL;
    return S_FALSE;
}

HRESULT CNFCCredential::Connect(IQueryContinueWithStatus* pqcws) {
    return S_OK;
}

HRESULT CNFCCredential::Disconnect() {
    return S_OK;
}

void CNFCCredential::SetAuthenticated(BOOL bAuth) {
    m_bAuthenticated = bAuth;

    if (m_pEvents && bAuth) {
        m_pEvents->SetFieldString(this, FI_STATUS, L"Authenticated - Logging in...");
    }
}

//
// Class Factory
//

CNFCCredentialProviderFactory::CNFCCredentialProviderFactory() : m_cRef(1) {
    InterlockedIncrement(&g_cRef);
}

CNFCCredentialProviderFactory::~CNFCCredentialProviderFactory() {
    InterlockedDecrement(&g_cRef);
}

ULONG CNFCCredentialProviderFactory::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

ULONG CNFCCredentialProviderFactory::Release() {
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0) {
        delete this;
    }
    return cRef;
}

HRESULT CNFCCredentialProviderFactory::QueryInterface(REFIID riid, void** ppv) {
    static const QITAB qit[] = {
        QITABENT(CNFCCredentialProviderFactory, IClassFactory),
        { 0 },
    };
    return QISearch(this, qit, riid, ppv);
}

HRESULT CNFCCredentialProviderFactory::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) {
    if (pUnkOuter) {
        return CLASS_E_NOAGGREGATION;
    }

    CNFCCredentialProvider* pProvider = new CNFCCredentialProvider();
    if (!pProvider) {
        return E_OUTOFMEMORY;
    }

    HRESULT hr = pProvider->QueryInterface(riid, ppv);
    pProvider->Release();
    return hr;
}

HRESULT CNFCCredentialProviderFactory::LockServer(BOOL bLock) {
    if (bLock) {
        InterlockedIncrement(&g_cRef);
    } else {
        InterlockedDecrement(&g_cRef);
    }
    return S_OK;
}

//
// DLL Exports
//

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        g_hInstance = hInstance;
        DisableThreadLibraryCalls(hInstance);
        break;
    }
    return TRUE;
}

STDAPI DllCanUnloadNow() {
    return (g_cRef == 0) ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (rclsid == CLSID_NFCCredentialProvider) {
        CNFCCredentialProviderFactory* pFactory = new CNFCCredentialProviderFactory();
        if (!pFactory) {
            return E_OUTOFMEMORY;
        }
        HRESULT hr = pFactory->QueryInterface(riid, ppv);
        pFactory->Release();
        return hr;
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}
