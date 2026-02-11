/*
 * VaultGateProvider.h — Windows Credential Provider for VaultGate
 *
 * Implements a Windows Credential Provider that adds a VaultGate
 * authentication tile to the Windows login screen. On failed authentication
 * (threshold exceeded), signals the VaultGate service to wipe the drive.
 *
 * Build with MSVC:
 *   cl /EHsc /LD VaultGateProvider.cpp /link /OUT:VaultGateProvider.dll
 *
 * Copyright 2025 — GPL-2.0+
 */

#ifndef VAULT_GATE_PROVIDER_H
#define VAULT_GATE_PROVIDER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <strsafe.h>

/* {A7B1C8D2-3E4F-5A6B-7C8D-9E0F1A2B3C4D} */
DEFINE_GUID(CLSID_VaultGateProvider,
    0xa7b1c8d2, 0x3e4f, 0x5a6b,
    0x7c, 0x8d, 0x9e, 0x0f, 0x1a, 0x2b, 0x3c, 0x4d);

/* Named pipe for communicating with the VaultGate service */
#define VG_PIPE_NAME L"\\\\.\\pipe\\VaultGateTrigger"

/* Commands sent over the pipe */
#define VG_CMD_TRIGGER_WIPE  "WIPE"
#define VG_CMD_AUTH_SUCCESS   "AUTH_OK"

/*
 * VaultGate Credential Provider
 * Implements ICredentialProvider interface
 */
class CVaultGateProvider : public ICredentialProvider
{
public:
    /* IUnknown */
    IFACEMETHODIMP_(ULONG) AddRef(void);
    IFACEMETHODIMP_(ULONG) Release(void);
    IFACEMETHODIMP QueryInterface(REFIID riid, void **ppv);

    /* ICredentialProvider */
    IFACEMETHODIMP SetUsageScenario(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(
        const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs);
    IFACEMETHODIMP Advise(
        ICredentialProviderEvents *pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise(void);
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD *pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(
        DWORD dwIndex,
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd);
    IFACEMETHODIMP GetCredentialCount(
        DWORD *pdwCount, DWORD *pdwDefault,
        BOOL *pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(
        DWORD dwIndex, ICredentialProviderCredential **ppcpc);

    CVaultGateProvider();

private:
    ~CVaultGateProvider();

    LONG                              m_cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;
    ICredentialProviderCredential     *m_pCredential;
};

/*
 * VaultGate Credential
 * Implements ICredentialProviderCredential
 */
class CVaultGateCredential : public ICredentialProviderCredential
{
public:
    /* IUnknown */
    IFACEMETHODIMP_(ULONG) AddRef(void);
    IFACEMETHODIMP_(ULONG) Release(void);
    IFACEMETHODIMP QueryInterface(REFIID riid, void **ppv);

    /* ICredentialProviderCredential */
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents *pcpce);
    IFACEMETHODIMP UnAdvise(void);
    IFACEMETHODIMP SetSelected(BOOL *pbAutoLogon);
    IFACEMETHODIMP SetDeselected(void);
    IFACEMETHODIMP GetFieldState(
        DWORD dwFieldID,
        CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis);
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, LPWSTR *ppsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP *phbmp);
    IFACEMETHODIMP GetCheckboxValue(
        DWORD dwFieldID, BOOL *pbChecked, LPWSTR *ppszLabel);
    IFACEMETHODIMP GetSubmitButtonValue(
        DWORD dwFieldID, DWORD *pdwAdjacentTo);
    IFACEMETHODIMP GetComboBoxValueCount(
        DWORD dwFieldID, DWORD *pcItems, DWORD *pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(
        DWORD dwFieldID, DWORD dwItem, LPWSTR *ppszItem);
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, LPCWSTR psz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(
        DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);
    IFACEMETHODIMP GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
        LPWSTR *ppszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(
        NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
        LPWSTR *ppszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon);

    CVaultGateCredential();

private:
    ~CVaultGateCredential();

    LONG   m_cRef;
    WCHAR  m_szPassword[256];
    int    m_nAttempts;
    int    m_nMaxAttempts;
    ICredentialProviderCredentialEvents *m_pCredEvents;

    /* Send command to VaultGate service */
    BOOL SendToService(const char *command);
    /* Load config and verify password */
    BOOL VerifyPassword(const WCHAR *password);
};

/* Field IDs for the credential tile */
enum VAULT_GATE_FIELD_ID {
    VGF_TITLE = 0,      /* "VaultGate Security" label */
    VGF_PASSWORD,        /* Password edit field */
    VGF_SUBMIT,          /* Submit button */
    VGF_STATUS,          /* Status text */
    VGF_COUNT
};

#endif /* VAULT_GATE_PROVIDER_H */
