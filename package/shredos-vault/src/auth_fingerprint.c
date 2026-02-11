#ifdef HAVE_FINGERPRINT

#include "auth_fingerprint.h"
#include "tui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fprint.h>

#define FP_STORAGE_DIR     "/etc/shredos-vault/fingerprints"
#define FP_ENROLLED_FILE   FP_STORAGE_DIR "/enrolled.dat"
#define FP_ENROLL_SCANS    5
#define FP_VERIFY_TIMEOUT  15 /* seconds */

static FpContext *fp_ctx = NULL;
static FpDevice  *fp_dev = NULL;

int vault_auth_fingerprint_init(void)
{
    fp_ctx = fp_context_new();
    if (!fp_ctx) {
        fprintf(stderr, "vault: failed to create fprint context\n");
        return -1;
    }

    /* Enumerate devices */
    GPtrArray *devices = fp_context_get_devices(fp_ctx);
    if (!devices || devices->len == 0) {
        fprintf(stderr, "vault: no fingerprint readers found\n");
        return -1;
    }

    /* Use first available device */
    fp_dev = g_ptr_array_index(devices, 0);
    if (!fp_dev) {
        fprintf(stderr, "vault: failed to get fingerprint device\n");
        return -1;
    }

    /* Open device */
    GError *error = NULL;
    if (!fp_device_open_sync(fp_dev, NULL, &error)) {
        fprintf(stderr, "vault: failed to open fingerprint device: %s\n",
                error ? error->message : "unknown error");
        if (error) g_error_free(error);
        return -1;
    }

    return 0;
}

void vault_auth_fingerprint_cleanup(void)
{
    if (fp_dev) {
        fp_device_close_sync(fp_dev, NULL, NULL);
        fp_dev = NULL;
    }
    if (fp_ctx) {
        g_object_unref(fp_ctx);
        fp_ctx = NULL;
    }
}

bool vault_auth_fingerprint_available(void)
{
    if (!fp_ctx) {
        if (vault_auth_fingerprint_init() != 0)
            return false;
    }

    /* Check if we have an enrolled print */
    if (access(FP_ENROLLED_FILE, R_OK) != 0)
        return false;

    return fp_dev != NULL;
}

/*
 * Load enrolled fingerprint from file.
 * Returns FpPrint* on success, NULL on failure.
 */
static FpPrint *load_enrolled_print(FpDevice *dev)
{
    unsigned char *data = NULL;
    size_t data_len = 0;

    FILE *fp = fopen(FP_ENROLLED_FILE, "rb");
    if (!fp)
        return NULL;

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    data_len = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (data_len == 0 || data_len > 1024 * 1024) { /* Sanity: max 1MB */
        fclose(fp);
        return NULL;
    }

    data = malloc(data_len);
    if (!data) {
        fclose(fp);
        return NULL;
    }

    if (fread(data, 1, data_len, fp) != data_len) {
        free(data);
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    FpPrint *print = NULL;
    GError *error = NULL;

    print = fp_print_deserialize(data, data_len, &error);
    free(data);

    if (!print) {
        fprintf(stderr, "vault: failed to deserialize fingerprint: %s\n",
                error ? error->message : "unknown");
        if (error) g_error_free(error);
        return NULL;
    }

    return print;
}

/*
 * Save a fingerprint to file.
 */
static int save_print(FpPrint *print)
{
    unsigned char *data = NULL;
    size_t data_len = 0;
    GError *error = NULL;

    if (!fp_print_serialize(print, &data, &data_len, &error)) {
        fprintf(stderr, "vault: failed to serialize print: %s\n",
                error ? error->message : "unknown");
        if (error) g_error_free(error);
        return -1;
    }

    mkdir(FP_STORAGE_DIR, 0700);

    FILE *fp = fopen(FP_ENROLLED_FILE, "wb");
    if (!fp) {
        g_free(data);
        return -1;
    }

    size_t written = fwrite(data, 1, data_len, fp);
    fclose(fp);
    g_free(data);

    chmod(FP_ENROLLED_FILE, 0600);

    return (written == data_len) ? 0 : -1;
}

auth_result_t vault_auth_fingerprint_verify(const vault_config_t *cfg)
{
    (void)cfg;

    if (!fp_dev) {
        if (vault_auth_fingerprint_init() != 0)
            return AUTH_ERROR;
    }

    FpPrint *enrolled = load_enrolled_print(fp_dev);
    if (!enrolled) {
        fprintf(stderr, "vault: no enrolled fingerprint found\n");
        return AUTH_ERROR;
    }

    vault_tui_status("Place your finger on the reader...");

    GError *error = NULL;
    gboolean match = FALSE;
    FpPrint *print_out = NULL;

    gboolean ret = fp_device_verify_sync(fp_dev, enrolled, NULL,
                                          NULL, NULL,
                                          &match, &print_out, &error);

    g_object_unref(enrolled);
    if (print_out)
        g_object_unref(print_out);

    if (!ret) {
        fprintf(stderr, "vault: fingerprint verify failed: %s\n",
                error ? error->message : "unknown");
        if (error) g_error_free(error);
        return AUTH_ERROR;
    }

    return match ? AUTH_SUCCESS : AUTH_FAILURE;
}

int vault_auth_fingerprint_enroll(const char *storage_dir)
{
    (void)storage_dir;

    if (!fp_dev) {
        if (vault_auth_fingerprint_init() != 0)
            return -1;
    }

    vault_tui_status("Starting fingerprint enrollment...");

    /* Create a template for the print */
    FpPrint *template = fp_print_new(fp_dev);

    GError *error = NULL;
    FpPrint *enrolled_print = NULL;

    vault_tui_status("Place your finger on the reader (scan 1 of %d)...",
                     FP_ENROLL_SCANS);

    gboolean ret = fp_device_enroll_sync(fp_dev, template, NULL,
                                          NULL, NULL,
                                          &enrolled_print, &error);

    g_object_unref(template);

    if (!ret || !enrolled_print) {
        fprintf(stderr, "vault: enrollment failed: %s\n",
                error ? error->message : "unknown");
        if (error) g_error_free(error);
        return -1;
    }

    /* Save the enrolled print */
    int save_ret = save_print(enrolled_print);
    g_object_unref(enrolled_print);

    if (save_ret != 0) {
        vault_tui_error("Failed to save fingerprint data!");
        return -1;
    }

    vault_tui_status("Fingerprint enrolled successfully!");
    sleep(2);
    return 0;
}

#endif /* HAVE_FINGERPRINT */
