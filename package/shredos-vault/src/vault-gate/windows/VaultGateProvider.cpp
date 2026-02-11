/*
 * VaultGateProvider.cpp — Windows Credential Provider for ShredOS Vault
 *
 * Implements a Windows Credential Provider that presents a ShredOS Vault
 * password tile on the login screen. Failed authentication past the
 * configured threshold triggers the wipe service.
 *
 * Uses the unified vault auth and config code (auth_password.h, config.h).
 *
 * Build (MSVC):
 *   cl /EHsc /LD /DUNICODE /D_UNICODE /DVAULT_PLATFORM_WINDOWS
 *      VaultGateProvider.cpp ..\..\auth_password.c ..\..\config.c
 *      ..\..\platform.c
 *      /link /OUT:VaultGateProvider.dll ole32.lib advapi32.lib crypt32.lib
 *
 * Register:
 *   regsvr32 VaultGateProvider.dll
 *   (or use the install.bat script)
 *
 * Copyright 2025 — GPL-2.0+
 */

#include "VaultGateProvider.h"
#include <shlwapi.h>
#include <wchar.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")

/* Include the real vault auth and config code */
extern "C" {
#include "../../auth_password.h"
#include "../../config.h"
#include "../../platform.h"
}

#define VG_CONFIG_PATH "C:\\ProgramData\\ShredOS-Vault\\vault.conf"

/* ------------------------------------------------------------------ */
/*  DLL reference counting                                             */
/* ------------------------------------------------------------------ */

static LONG g_cRef = 0;
static HINSTANCE g_hInstance = NULL;

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID)
{
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        g_hInstance = hInstance;
        DisableThreadLibraryCalls(hInstance);
        break;
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Field descriptors                                                  */
/* ------------------------------------------------------------------ */

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_FieldDescriptors[] = {
    { VGF_TITLE,    CPFT_LARGE_TEXT,   L"ShredOS Vault",   {0} },
    { VGF_PASSWORD, CPFT_PASSWORD_TEXT, L"Password",        {0} },
    { VGF_SUBMIT,   CPFT_SUBMIT_BUTTON, L"Authenticate",   {0} },
    { VGF_STATUS,   CPFT_SMALL_TEXT,   L"",                 {0} },
};

static const CREDENTIAL_PROVIDER_FIELD_STATE s_FieldStates[] = {
    CPFS_DISPLAY_IN_SELECTED_TILE,  /* Title */
    CPFS_DISPLAY_IN_SELECTED_TILE,  /* Password */
    CPFS_DISPLAY_IN_SELECTED_TILE,  /* Submit button */
    CPFS_DISPLAY_IN_SELECTED_TILE,  /* Status */
};

static const CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE s_FieldInteractive[] = {
    CPFIS_NONE,      /* Title: read-only */
    CPFIS_FOCUSED,   /* Password: focused for input */
    CPFIS_NONE,      /* Submit */
    CPFIS_NONE,      /* Status */
};

/* ================================================================== */
/*  CVaultGateProvider implementation                                  */
/* ================================================================== */

CVaultGateProvider::CVaultGateProvider()
    : m_cRef(1)
    , m_cpus(CPUS_INVALID)
    , m_pCredential(NULL)
{
    InterlockedIncrement(&g_cRef);
}

CVaultGateProvider::~CVaultGateProvider()
{
    if (m_pCredential) {
        m_pCredential->Release();
        m_pCredential = NULL;
    }
    InterlockedDecrement(&g_cRef);
}

ULONG CVaultGateProvider::AddRef()   { return InterlockedIncrement(&m_cRef); }
ULONG CVaultGateProvider::Release()  {
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0) delete this;
    return cRef;
}

HRESULT CVaultGateProvider::QueryInterface(REFIID riid, void **ppv)
{
    if (ppv == NULL) return E_INVALIDARG;
    *ppv = NULL;

    if (riid == IID_IUnknown || riid == IID_ICredentialProvider) {
        *ppv = static_cast<ICredentialProvider *>(this);
        AddRef();
        return S_OK;
    }
    return E_NOINTERFACE;
}

HRESULT CVaultGateProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD)
{
    m_cpus = cpus;

    switch (cpus) {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        /* Create our credential */
        if (m_pCredential == NULL) {
            CVaultGateCredential *pCred = new CVaultGateCredential();
            if (pCred) {
                m_pCredential = pCred;
                return S_OK;
            }
            return E_OUTOFMEMORY;
        }
        return S_OK;

    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
        return E_NOTIMPL;

    default:
        return E_INVALIDARG;
    }
}

HRESULT CVaultGateProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *)
{
    return E_NOTIMPL;
}

HRESULT CVaultGateProvider::Advise(ICredentialProviderEvents *, UINT_PTR)
{
    return S_OK;
}

HRESULT CVaultGateProvider::UnAdvise()
{
    return S_OK;
}

HRESULT CVaultGateProvider::GetFieldDescriptorCount(DWORD *pdwCount)
{
    *pdwCount = VGF_COUNT;
    return S_OK;
}

HRESULT CVaultGateProvider::GetFieldDescriptorAt(
    DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd)
{
    if (dwIndex >= VGF_COUNT || ppcpfd == NULL) return E_INVALIDARG;

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR *pfd =
        (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR *)CoTaskMemAlloc(
            sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
    if (!pfd) return E_OUTOFMEMORY;

    *pfd = s_FieldDescriptors[dwIndex];
    if (s_FieldDescriptors[dwIndex].pszLabel) {
        SHStrDupW(s_FieldDescriptors[dwIndex].pszLabel, &pfd->pszLabel);
    }

    *ppcpfd = pfd;
    return S_OK;
}

HRESULT CVaultGateProvider::GetCredentialCount(
    DWORD *pdwCount, DWORD *pdwDefault, BOOL *pbAutoLogonWithDefault)
{
    *pdwCount = 1;
    *pdwDefault = 0;
    *pbAutoLogonWithDefault = FALSE;
    return S_OK;
}

HRESULT CVaultGateProvider::GetCredentialAt(
    DWORD dwIndex, ICredentialProviderCredential **ppcpc)
{
    if (dwIndex != 0 || ppcpc == NULL) return E_INVALIDARG;
    if (m_pCredential == NULL) return E_UNEXPECTED;

    m_pCredential->AddRef();
    *ppcpc = m_pCredential;
    return S_OK;
}

/* ================================================================== */
/*  CVaultGateCredential implementation                                */
/* ================================================================== */

CVaultGateCredential::CVaultGateCredential()
    : m_cRef(1)
    , m_nAttempts(0)
    , m_nMaxAttempts(3)
    , m_pCredEvents(NULL)
{
    ZeroMemory(m_szPassword, sizeof(m_szPassword));
    InterlockedIncrement(&g_cRef);

    /* Load config using the real vault config API */
    vault_config_t cfg;
    vault_config_init(&cfg);
    if (vault_config_load(&cfg, VG_CONFIG_PATH) == 0) {
        m_nMaxAttempts = cfg.max_attempts;
        if (m_nMaxAttempts < 1) m_nMaxAttempts = 1;
    }
}

CVaultGateCredential::~CVaultGateCredential()
{
    SecureZeroMemory(m_szPassword, sizeof(m_szPassword));
    InterlockedDecrement(&g_cRef);
}

ULONG CVaultGateCredential::AddRef()  { return InterlockedIncrement(&m_cRef); }
ULONG CVaultGateCredential::Release() {
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0) delete this;
    return cRef;
}

HRESULT CVaultGateCredential::QueryInterface(REFIID riid, void **ppv)
{
    if (ppv == NULL) return E_INVALIDARG;
    *ppv = NULL;

    if (riid == IID_IUnknown ||
        riid == IID_ICredentialProviderCredential) {
        *ppv = static_cast<ICredentialProviderCredential *>(this);
        AddRef();
        return S_OK;
    }
    return E_NOINTERFACE;
}

HRESULT CVaultGateCredential::Advise(ICredentialProviderCredentialEvents *pcpce)
{
    if (m_pCredEvents) m_pCredEvents->Release();
    m_pCredEvents = pcpce;
    if (m_pCredEvents) m_pCredEvents->AddRef();
    return S_OK;
}

HRESULT CVaultGateCredential::UnAdvise()
{
    if (m_pCredEvents) {
        m_pCredEvents->Release();
        m_pCredEvents = NULL;
    }
    return S_OK;
}

HRESULT CVaultGateCredential::SetSelected(BOOL *pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

HRESULT CVaultGateCredential::SetDeselected()
{
    SecureZeroMemory(m_szPassword, sizeof(m_szPassword));
    if (m_pCredEvents)
        m_pCredEvents->SetFieldString(this, VGF_PASSWORD, L"");
    return S_OK;
}

HRESULT CVaultGateCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    if (dwFieldID >= VGF_COUNT) return E_INVALIDARG;
    *pcpfs  = s_FieldStates[dwFieldID];
    *pcpfis = s_FieldInteractive[dwFieldID];
    return S_OK;
}

HRESULT CVaultGateCredential::GetStringValue(DWORD dwFieldID, LPWSTR *ppsz)
{
    switch (dwFieldID) {
    case VGF_TITLE:
        return SHStrDupW(L"ShredOS Vault Security Lock", ppsz);
    case VGF_PASSWORD:
        return SHStrDupW(L"", ppsz);
    case VGF_STATUS: {
        WCHAR status[128];
        int remaining = m_nMaxAttempts - m_nAttempts;
        StringCchPrintfW(status, ARRAYSIZE(status),
                         L"Attempts remaining: %d", remaining);
        return SHStrDupW(status, ppsz);
    }
    default:
        return SHStrDupW(L"", ppsz);
    }
}

HRESULT CVaultGateCredential::GetBitmapValue(DWORD, HBITMAP *phbmp)
{
    *phbmp = NULL;
    return E_NOTIMPL;
}

HRESULT CVaultGateCredential::GetCheckboxValue(DWORD, BOOL *, LPWSTR *)
{
    return E_NOTIMPL;
}

HRESULT CVaultGateCredential::GetSubmitButtonValue(
    DWORD dwFieldID, DWORD *pdwAdjacentTo)
{
    if (dwFieldID == VGF_SUBMIT) {
        *pdwAdjacentTo = VGF_PASSWORD;
        return S_OK;
    }
    return E_INVALIDARG;
}

HRESULT CVaultGateCredential::GetComboBoxValueCount(DWORD, DWORD *, DWORD *)
{
    return E_NOTIMPL;
}

HRESULT CVaultGateCredential::GetComboBoxValueAt(DWORD, DWORD, LPWSTR *)
{
    return E_NOTIMPL;
}

HRESULT CVaultGateCredential::SetStringValue(DWORD dwFieldID, LPCWSTR psz)
{
    if (dwFieldID == VGF_PASSWORD) {
        StringCchCopyW(m_szPassword, ARRAYSIZE(m_szPassword), psz);
        return S_OK;
    }
    return E_INVALIDARG;
}

HRESULT CVaultGateCredential::SetCheckboxValue(DWORD, BOOL)
{
    return E_NOTIMPL;
}

HRESULT CVaultGateCredential::SetComboBoxSelectedValue(DWORD, DWORD)
{
    return E_NOTIMPL;
}

HRESULT CVaultGateCredential::CommandLinkClicked(DWORD)
{
    return E_NOTIMPL;
}

/* ---- Pipe communication with ShredOS Vault service ---- */

BOOL CVaultGateCredential::SendToService(const char *command)
{
    HANDLE hPipe = CreateFileW(VG_PIPE_NAME,
                               GENERIC_WRITE, 0, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) return FALSE;

    DWORD written;
    BOOL ok = WriteFile(hPipe, command, (DWORD)strlen(command),
                        &written, NULL);
    CloseHandle(hPipe);
    return ok;
}

/* ---- Password verification using real vault auth ---- */

BOOL CVaultGateCredential::VerifyPassword(const WCHAR *password)
{
    /* Convert to UTF-8 */
    char utf8_pw[256];
    if (WideCharToMultiByte(CP_UTF8, 0, password, -1,
                            utf8_pw, sizeof(utf8_pw), NULL, NULL) == 0) {
        return FALSE;
    }

    /* Load stored hash from config using the real vault config API */
    vault_config_t cfg;
    vault_config_init(&cfg);

    BOOL result = FALSE;

    if (vault_config_load(&cfg, VG_CONFIG_PATH) == 0 &&
        cfg.password_hash[0] != '\0') {
        /* Use the real vault password verification */
        result = (vault_auth_password_verify(&cfg, utf8_pw) == AUTH_SUCCESS)
                 ? TRUE : FALSE;
    }

    /* Securely clear password from memory */
    SecureZeroMemory(utf8_pw, sizeof(utf8_pw));
    vault_secure_memzero(cfg.password_hash, sizeof(cfg.password_hash));

    return result;
}

/* ---- Submit handler ---- */

HRESULT CVaultGateCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
    LPWSTR *ppszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    (void)pcpcs;

    m_nAttempts++;

    if (VerifyPassword(m_szPassword)) {
        /* Success — tell service, then allow Windows login */
        SendToService(VG_CMD_AUTH_SUCCESS);

        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        *ppszOptionalStatusText = NULL;
        *pcpsiOptionalStatusIcon = CPSI_SUCCESS;

        /* Clear password */
        SecureZeroMemory(m_szPassword, sizeof(m_szPassword));

        /* Return S_OK to dismiss the credential provider
         * and allow normal Windows login to proceed */
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        return S_OK;
    }

    /* Failure */
    SecureZeroMemory(m_szPassword, sizeof(m_szPassword));

    if (m_nAttempts >= m_nMaxAttempts) {
        /* Threshold exceeded — trigger wipe */
        SendToService(VG_CMD_TRIGGER_WIPE);

        SHStrDupW(L"SECURITY ALERT: Drive destruction initiated.",
                  ppszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    /* Show remaining attempts */
    WCHAR status[128];
    int remaining = m_nMaxAttempts - m_nAttempts;
    StringCchPrintfW(status, ARRAYSIZE(status),
                     L"Incorrect password. %d attempt%s remaining.",
                     remaining, remaining == 1 ? L"" : L"s");
    SHStrDupW(status, ppszOptionalStatusText);
    *pcpsiOptionalStatusIcon = CPSI_WARNING;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;

    /* Update status field */
    if (m_pCredEvents) {
        WCHAR fieldStatus[128];
        StringCchPrintfW(fieldStatus, ARRAYSIZE(fieldStatus),
                         L"Attempts remaining: %d", remaining);
        m_pCredEvents->SetFieldString(this, VGF_STATUS, fieldStatus);
    }

    return S_OK;
}

HRESULT CVaultGateCredential::ReportResult(
    NTSTATUS, NTSTATUS, LPWSTR *ppszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    *ppszOptionalStatusText = NULL;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    return S_OK;
}

/* ================================================================== */
/*  COM Class Factory                                                  */
/* ================================================================== */

class CVaultGateProviderFactory : public IClassFactory
{
public:
    CVaultGateProviderFactory() : m_cRef(1) { InterlockedIncrement(&g_cRef); }
    ~CVaultGateProviderFactory() { InterlockedDecrement(&g_cRef); }

    IFACEMETHODIMP_(ULONG) AddRef()  { return InterlockedIncrement(&m_cRef); }
    IFACEMETHODIMP_(ULONG) Release() {
        LONG cRef = InterlockedDecrement(&m_cRef);
        if (cRef == 0) delete this;
        return cRef;
    }
    IFACEMETHODIMP QueryInterface(REFIID riid, void **ppv) {
        if (ppv == NULL) return E_INVALIDARG;
        *ppv = NULL;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory *>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP CreateInstance(IUnknown *pUnkOuter, REFIID riid, void **ppv) {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        CVaultGateProvider *pProvider = new CVaultGateProvider();
        if (!pProvider) return E_OUTOFMEMORY;
        HRESULT hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
        return hr;
    }

    IFACEMETHODIMP LockServer(BOOL bLock) {
        if (bLock) InterlockedIncrement(&g_cRef);
        else       InterlockedDecrement(&g_cRef);
        return S_OK;
    }

private:
    LONG m_cRef;
};

/* ================================================================== */
/*  DLL exports                                                        */
/* ================================================================== */

STDAPI DllCanUnloadNow()
{
    return (g_cRef > 0) ? S_FALSE : S_OK;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void **ppv)
{
    if (ppv == NULL) return E_INVALIDARG;
    *ppv = NULL;

    if (rclsid == CLSID_VaultGateProvider) {
        CVaultGateProviderFactory *pFactory = new CVaultGateProviderFactory();
        if (!pFactory) return E_OUTOFMEMORY;
        HRESULT hr = pFactory->QueryInterface(riid, ppv);
        pFactory->Release();
        return hr;
    }

    return CLASS_E_CLASSNOTAVAILABLE;
}
