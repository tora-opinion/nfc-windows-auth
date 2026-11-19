#include "Provider.h"
#include "Module.h"

#include <windows.h>
#include <new>
#include <strsafe.h>

namespace NfcAuth
{
    const CLSID CLSID_NfcCredentialProvider =
        { 0x1bdc8b64, 0x62be, 0x46ad, { 0xa1, 0x9b, 0xb6, 0xd0, 0x6f, 0xd2, 0x0a, 0xa7 } };

    namespace
    {
        HINSTANCE g_instance = nullptr;
        volatile LONG g_objectCount = 0;
        volatile LONG g_serverLocks = 0;
        volatile LONG g_liveWorkers = 0;

        class ClassFactory final : public IClassFactory
        {
        public:
            ClassFactory() noexcept : refCount_(1) { ModuleObjectCreated(); }

            HRESULT QueryInterface(REFIID riid, void** object) override
            {
                if (!object) return E_POINTER;
                *object = nullptr;
                if (riid != IID_IUnknown && riid != IID_IClassFactory) return E_NOINTERFACE;
                *object = static_cast<IClassFactory*>(this);
                AddRef();
                return S_OK;
            }

            ULONG AddRef() override
            {
                return static_cast<ULONG>(InterlockedIncrement(&refCount_));
            }

            ULONG Release() override
            {
                const LONG refs = InterlockedDecrement(&refCount_);
                if (refs == 0) delete this;
                return static_cast<ULONG>(refs);
            }

            HRESULT CreateInstance(IUnknown* outer, REFIID riid, void** object) override
            {
                if (!object) return E_POINTER;
                *object = nullptr;
                if (outer) return CLASS_E_NOAGGREGATION;
                auto* provider = new (std::nothrow) Provider();
                if (!provider) return E_OUTOFMEMORY;
                const HRESULT hr = provider->QueryInterface(riid, object);
                provider->Release();
                return hr;
            }

            HRESULT LockServer(BOOL lock) override
            {
                if (lock)
                {
                    InterlockedIncrement(&g_serverLocks);
                    ModuleObjectCreated();
                }
                else
                {
                    LONG current = InterlockedCompareExchange(&g_serverLocks, 0, 0);
                    while (current > 0)
                    {
                        const LONG observed = InterlockedCompareExchange(
                            &g_serverLocks, current - 1, current);
                        if (observed == current)
                        {
                            ModuleObjectDestroyed();
                            break;
                        }
                        current = observed;
                    }
                }
                return S_OK;
            }

        private:
            ~ClassFactory() noexcept { ModuleObjectDestroyed(); }
            LONG refCount_;
        };

        HRESULT WriteStringValue(HKEY key, LPCWSTR valueName, const wchar_t* value) noexcept
        {
            const DWORD bytes = static_cast<DWORD>((lstrlenW(value) + 1) * sizeof(wchar_t));
            const LSTATUS status = RegSetValueExW(key, valueName, 0, REG_SZ,
                reinterpret_cast<const BYTE*>(value), bytes);
            return status == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(status);
        }

        HRESULT DeleteTree(HKEY root, const wchar_t* path) noexcept
        {
            const LSTATUS status = RegDeleteTreeW(root, path);
            return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND
                ? S_OK : HRESULT_FROM_WIN32(status);
        }
    }

    void ModuleObjectCreated() noexcept { InterlockedIncrement(&g_objectCount); }
    void ModuleObjectDestroyed() noexcept { InterlockedDecrement(&g_objectCount); }
    void ModuleWorkerStarted() noexcept { InterlockedIncrement(&g_liveWorkers); }
    void ModuleWorkerStopped() noexcept { InterlockedDecrement(&g_liveWorkers); }
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        NfcAuth::g_instance = instance;
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID classId, REFIID interfaceId, void** object)
{
    if (!object) return E_POINTER;
    *object = nullptr;
    if (classId != NfcAuth::CLSID_NfcCredentialProvider) return CLASS_E_CLASSNOTAVAILABLE;

    auto* factory = new (std::nothrow) NfcAuth::ClassFactory();
    if (!factory) return E_OUTOFMEMORY;
    const HRESULT hr = factory->QueryInterface(interfaceId, object);
    factory->Release();
    return hr;
}

STDAPI DllCanUnloadNow()
{
    return (InterlockedCompareExchange(&NfcAuth::g_objectCount, 0, 0) == 0 &&
            InterlockedCompareExchange(&NfcAuth::g_serverLocks, 0, 0) == 0 &&
            InterlockedCompareExchange(&NfcAuth::g_liveWorkers, 0, 0) == 0)
        ? S_OK : S_FALSE;
}

STDAPI DllRegisterServer()
{
    using namespace NfcAuth;
    wchar_t modulePath[MAX_PATH] = {};
    if (!GetModuleFileNameW(g_instance, modulePath, ARRAYSIZE(modulePath)))
        return HRESULT_FROM_WIN32(GetLastError());

    wchar_t clsidText[64] = {};
    if (!StringFromGUID2(CLSID_NfcCredentialProvider, clsidText, ARRAYSIZE(clsidText)))
        return E_FAIL;

    wchar_t credentialProviderKey[256] = {};
    wchar_t clsidKey[128] = {};
    HRESULT hr = StringCchPrintfW(credentialProviderKey, ARRAYSIZE(credentialProviderKey),
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s",
        clsidText);
    if (FAILED(hr)) return hr;
    hr = StringCchPrintfW(clsidKey, ARRAYSIZE(clsidKey), L"CLSID\\%s\\InprocServer32", clsidText);
    if (FAILED(hr)) return hr;

    HKEY cpKey = nullptr;
    LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, credentialProviderKey, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &cpKey, nullptr);
    if (status != ERROR_SUCCESS) return HRESULT_FROM_WIN32(status);
    hr = WriteStringValue(cpKey, nullptr, L"NFC Credential Provider");
    RegCloseKey(cpKey);
    if (FAILED(hr))
    {
        DeleteTree(HKEY_LOCAL_MACHINE, credentialProviderKey);
        return hr;
    }

    HKEY inprocKey = nullptr;
    status = RegCreateKeyExW(HKEY_CLASSES_ROOT, clsidKey, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &inprocKey, nullptr);
    if (status != ERROR_SUCCESS)
    {
        DeleteTree(HKEY_LOCAL_MACHINE, credentialProviderKey);
        return HRESULT_FROM_WIN32(status);
    }
    hr = WriteStringValue(inprocKey, nullptr, modulePath);
    if (SUCCEEDED(hr)) hr = WriteStringValue(inprocKey, L"ThreadingModel", L"Apartment");
    RegCloseKey(inprocKey);
    if (FAILED(hr))
    {
        DeleteTree(HKEY_LOCAL_MACHINE, credentialProviderKey);
        DeleteTree(HKEY_CLASSES_ROOT, clsidKey);
        wchar_t clsidRoot[96] = {};
        if (SUCCEEDED(StringCchPrintfW(clsidRoot, ARRAYSIZE(clsidRoot), L"CLSID\\%s", clsidText)))
            DeleteTree(HKEY_CLASSES_ROOT, clsidRoot);
        return hr;
    }

    return S_OK;
}

STDAPI DllUnregisterServer()
{
    using namespace NfcAuth;
    wchar_t clsidText[64] = {};
    if (!StringFromGUID2(CLSID_NfcCredentialProvider, clsidText, ARRAYSIZE(clsidText))) return E_FAIL;

    wchar_t credentialProviderKey[256] = {};
    wchar_t clsidRoot[96] = {};
    HRESULT hr = StringCchPrintfW(credentialProviderKey, ARRAYSIZE(credentialProviderKey),
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s",
        clsidText);
    if (FAILED(hr)) return hr;
    hr = StringCchPrintfW(clsidRoot, ARRAYSIZE(clsidRoot), L"CLSID\\%s", clsidText);
    if (FAILED(hr)) return hr;

    const HRESULT cpResult = DeleteTree(HKEY_LOCAL_MACHINE, credentialProviderKey);
    const HRESULT clsidResult = DeleteTree(HKEY_CLASSES_ROOT, clsidRoot);
    return FAILED(cpResult) ? cpResult : clsidResult;
}
