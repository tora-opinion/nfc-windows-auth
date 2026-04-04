/**
 * NfcCredentialProvider.cpp
 *
 * Windows Credential Provider that auto-authenticates when the Python NFC daemon
 * writes a valid tap event to the registry within the last 10 seconds.
 *
 * Registry layout (HKCU\Software\NfcAuth\):
 *   State\LastIdmHash   REG_SZ    SHA-256 hex of IDm
 *   State\LastTapTime   REG_QWORD Unix time in ms
 *   State\AuthValid     REG_DWORD 1 = registered card tapped, 0 = not
 *   Registered\EncryptedPin  REG_BINARY  DPAPI(CRYPTPROTECT_LOCAL_MACHINE) encrypted password
 *
 * CLSID: {A5E8C3B2-1234-5678-ABCD-0F1E2D3C4B5A}
 */

#define SECURITY_WIN32
#define INITGUID

#include <windows.h>
#include <initguid.h>
#include <credentialprovider.h>
#include <wincrypt.h>
#include <winreg.h>
#include <shlwapi.h>
#include <ntsecapi.h>
#include <strsafe.h>
#include <new>
#include <string>
#include <vector>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "secur32.lib")

// {A5E8C3B2-1234-5678-ABCD-0F1E2D3C4B5A}
DEFINE_GUID(CLSID_NfcCredentialProvider,
    0xA5E8C3B2, 0x1234, 0x5678,
    0xAB, 0xCD, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A);

static HINSTANCE g_hInst  = nullptr;
static LONG      g_cDllRef = 0;

constexpr DWORD  NFC_VALID_MS = 10000; // 10 seconds
// CRYPTPROTECT_LOCAL_MACHINE は wincrypt.h で定義済み (0x4)

// CPFG_LOGON_PASSWORD: {60624CFD-31D4-4690-ABFE-65618F4DE7E4}
// credentialprovider.h は EXTERN_C 宣言のみのため手動定義
static const GUID CPFG_LOGON_PASSWORD =
    { 0x60624cfd, 0x31d4, 0x4690, { 0xab, 0xfe, 0x65, 0x61, 0x8f, 0x4d, 0xe7, 0xe4 } };

// ---------------------------------------------------------------------------
// Registry / NFC helpers
// ---------------------------------------------------------------------------

static bool CheckNfcState()
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\NfcAuth\\State",
                      0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD authValid = 0;
    DWORD cbData    = sizeof(authValid);
    RegQueryValueExW(hKey, L"AuthValid", nullptr, nullptr,
                     reinterpret_cast<LPBYTE>(&authValid), &cbData);

    ULONGLONG tapTime = 0;
    cbData = sizeof(tapTime);
    RegQueryValueExW(hKey, L"LastTapTime", nullptr, nullptr,
                     reinterpret_cast<LPBYTE>(&tapTime), &cbData);

    RegCloseKey(hKey);

    if (authValid != 1) return false;

    // Current time as Unix ms
    SYSTEMTIME st; GetSystemTime(&st);
    FILETIME   ft; SystemTimeToFileTime(&st, &ft);
    ULONGLONG  ft64 = (static_cast<ULONGLONG>(ft.dwHighDateTime) << 32)
                    |  static_cast<ULONGLONG>(ft.dwLowDateTime);
    ULONGLONG  nowMs = (ft64 - 116444736000000000ULL) / 10000ULL;

    return (nowMs >= tapTime) && (nowMs - tapTime < NFC_VALID_MS);
}

static bool GetDecryptedPassword(std::wstring& outPassword)
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\NfcAuth\\Registered",
                      0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD cbData = 0;
    if (RegQueryValueExW(hKey, L"EncryptedPin", nullptr, nullptr,
                         nullptr, &cbData) != ERROR_SUCCESS || cbData == 0)
    {
        RegCloseKey(hKey);
        return false;
    }

    std::vector<BYTE> enc(cbData);
    bool ok = (RegQueryValueExW(hKey, L"EncryptedPin", nullptr, nullptr,
                                enc.data(), &cbData) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    if (!ok) return false;

    DATA_BLOB blobIn  = { static_cast<DWORD>(enc.size()), enc.data() };
    DATA_BLOB blobOut = {};
    if (!CryptUnprotectData(&blobIn, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_LOCAL_MACHINE, &blobOut))
        return false;

    // UTF-8 -> UTF-16
    int wLen = MultiByteToWideChar(CP_UTF8, 0,
                                   reinterpret_cast<LPCCH>(blobOut.pbData),
                                   static_cast<int>(blobOut.cbData),
                                   nullptr, 0);
    outPassword.resize(static_cast<size_t>(wLen));
    MultiByteToWideChar(CP_UTF8, 0,
                        reinterpret_cast<LPCCH>(blobOut.pbData),
                        static_cast<int>(blobOut.cbData),
                        &outPassword[0], wLen);

    SecureZeroMemory(blobOut.pbData, blobOut.cbData);
    LocalFree(blobOut.pbData);
    return true;
}

/**
 * Pack KERB_INTERACTIVE_UNLOCK_LOGON with pointers converted to buffer offsets.
 * Caller must CoTaskMemFree(*ppBuffer).
 */
static HRESULT PackKerbLogon(const std::wstring& domain,
                              const std::wstring& username,
                              const std::wstring& password,
                              BYTE** ppBuffer, DWORD* pcbBuffer)
{
    const DWORD cbDomain   = static_cast<DWORD>((domain.size()   + 1) * sizeof(WCHAR));
    const DWORD cbUsername = static_cast<DWORD>((username.size() + 1) * sizeof(WCHAR));
    const DWORD cbPassword = static_cast<DWORD>((password.size() + 1) * sizeof(WCHAR));
    const DWORD cbTotal    = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON)
                           + cbDomain + cbUsername + cbPassword;

    auto* pBuf = static_cast<BYTE*>(CoTaskMemAlloc(cbTotal));
    if (!pBuf) return E_OUTOFMEMORY;
    ZeroMemory(pBuf, cbTotal);

    auto* pkiul = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(pBuf);
    pkiul->Logon.MessageType = KerbInteractiveLogon;

    BYTE* pCur = pBuf + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);

    // Domain (stored as byte offset from buffer start)
    pkiul->Logon.LogonDomainName.Length        = static_cast<USHORT>(cbDomain - sizeof(WCHAR));
    pkiul->Logon.LogonDomainName.MaximumLength = static_cast<USHORT>(cbDomain);
    pkiul->Logon.LogonDomainName.Buffer        = reinterpret_cast<PWSTR>(pCur - pBuf);
    CopyMemory(pCur, domain.c_str(), cbDomain);
    pCur += cbDomain;

    // Username
    pkiul->Logon.UserName.Length        = static_cast<USHORT>(cbUsername - sizeof(WCHAR));
    pkiul->Logon.UserName.MaximumLength = static_cast<USHORT>(cbUsername);
    pkiul->Logon.UserName.Buffer        = reinterpret_cast<PWSTR>(pCur - pBuf);
    CopyMemory(pCur, username.c_str(), cbUsername);
    pCur += cbUsername;

    // Password
    pkiul->Logon.Password.Length        = static_cast<USHORT>(cbPassword - sizeof(WCHAR));
    pkiul->Logon.Password.MaximumLength = static_cast<USHORT>(cbPassword);
    pkiul->Logon.Password.Buffer        = reinterpret_cast<PWSTR>(pCur - pBuf);
    CopyMemory(pCur, password.c_str(), cbPassword);

    *ppBuffer  = pBuf;
    *pcbBuffer = cbTotal;
    return S_OK;
}

static ULONG GetNtlmPackageId()
{
    HANDLE hLsa = nullptr;
    if (LsaConnectUntrusted(&hLsa) != 0) return 0;
    ULONG pkgId = 0;
    LSA_STRING pkg = { 4, 5, const_cast<PCHAR>("NTLM") };
    LsaLookupAuthenticationPackage(hLsa, &pkg, &pkgId);
    LsaDeregisterLogonProcess(hLsa);
    return pkgId;
}

// ---------------------------------------------------------------------------
// Field descriptor (1 hidden password field)
// ---------------------------------------------------------------------------

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_FieldDesc =
    { 0, CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L""), CPFG_LOGON_PASSWORD };

// ---------------------------------------------------------------------------
// CNfcCredential
// ---------------------------------------------------------------------------

class CNfcCredential final : public ICredentialProviderCredential
{
public:
    CNfcCredential() : m_cRef(1), m_pEvents(nullptr) {}

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential)
        {
            *ppv = static_cast<ICredentialProviderCredential*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef()  override { return InterlockedIncrement(&m_cRef); }
    IFACEMETHODIMP_(ULONG) Release() override
    {
        LONG c = InterlockedDecrement(&m_cRef);
        if (c == 0) delete this;
        return c;
    }

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pEvents) override
    {
        if (m_pEvents) m_pEvents->Release();
        m_pEvents = pEvents;
        if (m_pEvents) m_pEvents->AddRef();
        return S_OK;
    }

    IFACEMETHODIMP UnAdvise() override
    {
        if (m_pEvents) { m_pEvents->Release(); m_pEvents = nullptr; }
        return S_OK;
    }

    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon) override
    {
        *pbAutoLogon = CheckNfcState() ? TRUE : FALSE;
        return S_OK;
    }

    IFACEMETHODIMP SetDeselected() override { return S_OK; }

    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
                                  CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                  CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) override
    {
        if (dwFieldID != 0) return E_INVALIDARG;
        *pcpfs  = CPFS_HIDDEN;
        *pcpfis = CPFIS_NONE;
        return S_OK;
    }

    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz) override
    {
        if (dwFieldID != 0) return E_INVALIDARG;
        std::wstring pass;
        if (!GetDecryptedPassword(pass)) return E_FAIL;
        HRESULT hr = SHStrDupW(pass.c_str(), ppwsz);
        SecureZeroMemory(&pass[0], pass.size() * sizeof(WCHAR));
        return hr;
    }

    IFACEMETHODIMP GetBitmapValue(DWORD, HBITMAP*)              override { return E_NOTIMPL; }
    IFACEMETHODIMP GetCheckboxValue(DWORD, BOOL*, PWSTR*)       override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueCount(DWORD, DWORD*, DWORD*) override { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueAt(DWORD, DWORD, PWSTR*)     override { return E_NOTIMPL; }
    IFACEMETHODIMP GetSubmitButtonValue(DWORD, DWORD*)          override { return E_NOTIMPL; }
    IFACEMETHODIMP SetStringValue(DWORD, PCWSTR)                override { return S_OK; }
    IFACEMETHODIMP SetCheckboxValue(DWORD, BOOL)                override { return E_NOTIMPL; }
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD, DWORD)       override { return E_NOTIMPL; }
    IFACEMETHODIMP CommandLinkClicked(DWORD)                    override { return E_NOTIMPL; }

    IFACEMETHODIMP GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*   pcpcs,
        PWSTR*                                          ppwszStatus,
        CREDENTIAL_PROVIDER_STATUS_ICON*                pcpsiStatus) override
    {
        *ppwszStatus = nullptr;
        *pcpsiStatus = CPSI_NONE;
        *pcpgsr      = CPGSR_NO_CREDENTIAL_NOT_FINISHED;

        if (!CheckNfcState())
        {
            *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
            return S_FALSE;
        }

        std::wstring pass;
        if (!GetDecryptedPassword(pass)) return E_FAIL;

        WCHAR szUser[256]   = {};
        WCHAR szDomain[256] = {};
        DWORD cch = ARRAYSIZE(szUser);
        GetUserNameW(szUser, &cch);
        cch = ARRAYSIZE(szDomain);
        GetComputerNameW(szDomain, &cch);

        BYTE*  pBuf  = nullptr;
        DWORD  cbBuf = 0;
        HRESULT hr = PackKerbLogon(szDomain, szUser, pass, &pBuf, &cbBuf);
        SecureZeroMemory(&pass[0], pass.size() * sizeof(WCHAR));
        if (FAILED(hr)) return hr;

        pcpcs->ulAuthenticationPackage = GetNtlmPackageId();
        pcpcs->cbSerialization         = cbBuf;
        pcpcs->rgbSerialization        = pBuf;
        pcpcs->clsidCredentialProvider = CLSID_NfcCredentialProvider;
        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        return S_OK;
    }

    IFACEMETHODIMP ReportResult(NTSTATUS, NTSTATUS, PWSTR*,
                                 CREDENTIAL_PROVIDER_STATUS_ICON*) override
    {
        return S_OK;
    }

private:
    ~CNfcCredential()
    {
        if (m_pEvents) m_pEvents->Release();
    }

    LONG m_cRef;
    ICredentialProviderCredentialEvents* m_pEvents;
};

// ---------------------------------------------------------------------------
// CNfcCredentialProvider
// ---------------------------------------------------------------------------

class CNfcCredentialProvider final : public ICredentialProvider
{
public:
    CNfcCredentialProvider() : m_cRef(1), m_pEvents(nullptr), m_pCred(nullptr),
                               m_cpus(CPUS_INVALID) {}

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (riid == IID_IUnknown || riid == IID_ICredentialProvider)
        {
            *ppv = static_cast<ICredentialProvider*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef()  override { return InterlockedIncrement(&m_cRef); }
    IFACEMETHODIMP_(ULONG) Release() override
    {
        LONG c = InterlockedDecrement(&m_cRef);
        if (c == 0) delete this;
        return c;
    }

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                    DWORD) override
    {
        m_cpus = cpus;
        return (cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION)
               ? S_OK : E_NOTIMPL;
    }

    IFACEMETHODIMP SetSerialization(
        const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override
    {
        return E_NOTIMPL;
    }

    IFACEMETHODIMP Advise(ICredentialProviderEvents* pEvents, UINT_PTR) override
    {
        if (m_pEvents) m_pEvents->Release();
        m_pEvents = pEvents;
        if (m_pEvents) m_pEvents->AddRef();
        return S_OK;
    }

    IFACEMETHODIMP UnAdvise() override
    {
        if (m_pEvents) { m_pEvents->Release(); m_pEvents = nullptr; }
        return S_OK;
    }

    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount) override
    {
        *pdwCount = 1;
        return S_OK;
    }

    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex,
                                         CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppDesc) override
    {
        if (dwIndex != 0 || !ppDesc) return E_INVALIDARG;
        auto* p = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
            CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
        if (!p) return E_OUTOFMEMORY;
        *p = s_FieldDesc;
        HRESULT hr = SHStrDupW(s_FieldDesc.pszLabel, &p->pszLabel);
        if (FAILED(hr)) { CoTaskMemFree(p); return hr; }
        *ppDesc = p;
        return S_OK;
    }

    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount,
                                       DWORD* pdwDefault,
                                       BOOL*  pbAutoLogon) override
    {
        bool valid = CheckNfcState();
        *pdwCount   = valid ? 1 : 0;
        *pdwDefault = valid ? 0 : CREDENTIAL_PROVIDER_NO_DEFAULT;
        *pbAutoLogon = valid ? TRUE : FALSE;
        return S_OK;
    }

    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex,
                                    ICredentialProviderCredential** ppcpc) override
    {
        if (dwIndex != 0 || !CheckNfcState()) return E_INVALIDARG;

        if (!m_pCred)
        {
            m_pCred = new (std::nothrow) CNfcCredential();
            if (!m_pCred) return E_OUTOFMEMORY;
        }
        return m_pCred->QueryInterface(IID_ICredentialProviderCredential,
                                       reinterpret_cast<void**>(ppcpc));
    }

private:
    ~CNfcCredentialProvider()
    {
        if (m_pCred)   m_pCred->Release();
        if (m_pEvents) m_pEvents->Release();
    }

    LONG                               m_cRef;
    ICredentialProviderEvents*         m_pEvents;
    CNfcCredential*                    m_pCred;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;
};

// ---------------------------------------------------------------------------
// IClassFactory
// ---------------------------------------------------------------------------

class CNfcCredentialProviderFactory final : public IClassFactory
{
public:
    CNfcCredentialProviderFactory() : m_cRef(1) {}

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (riid == IID_IUnknown || riid == IID_IClassFactory)
        {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef()  override { return InterlockedIncrement(&m_cRef); }
    IFACEMETHODIMP_(ULONG) Release() override
    {
        LONG c = InterlockedDecrement(&m_cRef);
        if (c == 0) delete this;
        return c;
    }

    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) override
    {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        auto* p = new (std::nothrow) CNfcCredentialProvider();
        if (!p) return E_OUTOFMEMORY;
        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }

    IFACEMETHODIMP LockServer(BOOL bLock) override
    {
        if (bLock) InterlockedIncrement(&g_cDllRef);
        else       InterlockedDecrement(&g_cDllRef);
        return S_OK;
    }

private:
    ~CNfcCredentialProviderFactory() = default;
    LONG m_cRef;
};

// ---------------------------------------------------------------------------
// DLL Exports
// ---------------------------------------------------------------------------

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        g_hInst = hInst;
        DisableThreadLibraryCalls(hInst);
    }
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (rclsid != CLSID_NfcCredentialProvider) return CLASS_E_CLASSNOTAVAILABLE;
    auto* pFactory = new (std::nothrow) CNfcCredentialProviderFactory();
    if (!pFactory) return E_OUTOFMEMORY;
    HRESULT hr = pFactory->QueryInterface(riid, ppv);
    pFactory->Release();
    return hr;
}

STDAPI DllCanUnloadNow()
{
    return (g_cDllRef == 0) ? S_OK : S_FALSE;
}

STDAPI DllRegisterServer()
{
    WCHAR szPath[MAX_PATH] = {};
    if (!GetModuleFileNameW(g_hInst, szPath, ARRAYSIZE(szPath)))
        return HRESULT_FROM_WIN32(GetLastError());

    WCHAR szClsid[64] = {};
    StringFromGUID2(CLSID_NfcCredentialProvider, szClsid, ARRAYSIZE(szClsid));

    // Register InprocServer32
    WCHAR szKey[256] = {};
    StringCchPrintfW(szKey, ARRAYSIZE(szKey), L"CLSID\\%s\\InprocServer32", szClsid);
    HKEY hKey = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, szKey, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr)
        != ERROR_SUCCESS)
        return E_ACCESSDENIED;

    RegSetValueExW(hKey, nullptr, 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(szPath),
                   static_cast<DWORD>((wcslen(szPath) + 1) * sizeof(WCHAR)));
    const WCHAR* szApart = L"Apartment";
    RegSetValueExW(hKey, L"ThreadingModel", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(szApart),
                   static_cast<DWORD>((wcslen(szApart) + 1) * sizeof(WCHAR)));
    RegCloseKey(hKey);

    // Register as Credential Provider
    StringCchPrintfW(szKey, ARRAYSIZE(szKey),
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication"
        L"\\Credential Providers\\%s", szClsid);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, szKey, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr)
        != ERROR_SUCCESS)
        return E_ACCESSDENIED;

    const WCHAR* szName = L"NFC Credential Provider";
    RegSetValueExW(hKey, nullptr, 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(szName),
                   static_cast<DWORD>((wcslen(szName) + 1) * sizeof(WCHAR)));
    RegCloseKey(hKey);

    return S_OK;
}

STDAPI DllUnregisterServer()
{
    WCHAR szClsid[64] = {};
    StringFromGUID2(CLSID_NfcCredentialProvider, szClsid, ARRAYSIZE(szClsid));

    WCHAR szKey[256] = {};
    StringCchPrintfW(szKey, ARRAYSIZE(szKey), L"CLSID\\%s", szClsid);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, szKey);

    StringCchPrintfW(szKey, ARRAYSIZE(szKey),
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication"
        L"\\Credential Providers\\%s", szClsid);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, szKey);

    return S_OK;
}
