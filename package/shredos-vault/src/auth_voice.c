#ifdef HAVE_VOICE

#include "auth_voice.h"
#include "tui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <portaudio.h>
#include <pocketsphinx.h>

#define SAMPLE_RATE       16000
#define FRAMES_PER_BUFFER 512
#define RECORD_SECONDS    5
#define MATCH_THRESHOLD   0.6  /* 60% similarity required */

static ps_decoder_t *ps_decoder = NULL;
static int pa_initialized = 0;

/*
 * Levenshtein distance for fuzzy string matching.
 * Returns edit distance between two strings.
 */
static int levenshtein(const char *s, const char *t)
{
    int slen = (int)strlen(s);
    int tlen = (int)strlen(t);

    /* Allocate matrix */
    int *d = calloc((size_t)(slen + 1) * (size_t)(tlen + 1), sizeof(int));
    if (!d) return slen > tlen ? slen : tlen;

    for (int i = 0; i <= slen; i++) d[i * (tlen + 1)] = i;
    for (int j = 0; j <= tlen; j++) d[j] = j;

    for (int i = 1; i <= slen; i++) {
        for (int j = 1; j <= tlen; j++) {
            int cost = (tolower((unsigned char)s[i-1]) ==
                        tolower((unsigned char)t[j-1])) ? 0 : 1;

            int del = d[(i-1) * (tlen+1) + j] + 1;
            int ins = d[i * (tlen+1) + (j-1)] + 1;
            int sub = d[(i-1) * (tlen+1) + (j-1)] + cost;

            int min = del < ins ? del : ins;
            d[i * (tlen+1) + j] = min < sub ? min : sub;
        }
    }

    int result = d[slen * (tlen + 1) + tlen];
    free(d);
    return result;
}

/*
 * Calculate similarity ratio between two strings (0.0 to 1.0).
 */
static double similarity(const char *s1, const char *s2)
{
    int len1 = (int)strlen(s1);
    int len2 = (int)strlen(s2);
    int maxlen = len1 > len2 ? len1 : len2;

    if (maxlen == 0) return 1.0;

    int dist = levenshtein(s1, s2);
    return 1.0 - ((double)dist / (double)maxlen);
}

int vault_auth_voice_init(void)
{
    /* Initialize PortAudio */
    PaError err = Pa_Initialize();
    if (err != paNoError) {
        fprintf(stderr, "vault: PortAudio init failed: %s\n",
                Pa_GetErrorText(err));
        return -1;
    }
    pa_initialized = 1;

    /* Initialize PocketSphinx */
    ps_config_t *config = ps_config_init(NULL);
    if (!config) {
        fprintf(stderr, "vault: PocketSphinx config failed\n");
        return -1;
    }

    /* Use default English acoustic model */
    ps_config_set_str(config, "hmm",
                       MODELDIR "/en-us/en-us");
    ps_config_set_str(config, "lm",
                       MODELDIR "/en-us/en-us.lm.bin");
    ps_config_set_str(config, "dict",
                       MODELDIR "/en-us/cmudict-en-us.dict");

    /* Suppress verbose output */
    ps_config_set_str(config, "logfn", "/dev/null");

    ps_decoder = ps_init(config);
    if (!ps_decoder) {
        fprintf(stderr, "vault: PocketSphinx decoder init failed\n");
        return -1;
    }

    return 0;
}

void vault_auth_voice_cleanup(void)
{
    if (ps_decoder) {
        ps_free(ps_decoder);
        ps_decoder = NULL;
    }
    if (pa_initialized) {
        Pa_Terminate();
        pa_initialized = 0;
    }
}

bool vault_auth_voice_available(void)
{
    if (!pa_initialized) {
        if (vault_auth_voice_init() != 0)
            return false;
    }

    /* Check if any input device is available */
    int num_devices = Pa_GetDeviceCount();
    for (int i = 0; i < num_devices; i++) {
        const PaDeviceInfo *info = Pa_GetDeviceInfo(i);
        if (info && info->maxInputChannels > 0)
            return true;
    }

    return false;
}

/*
 * Record audio from microphone into buffer.
 * Returns number of samples recorded, or -1 on error.
 */
static int record_audio(int16_t *buffer, int max_samples)
{
    PaStream *stream = NULL;
    PaError err;

    PaStreamParameters input_params;
    memset(&input_params, 0, sizeof(input_params));
    input_params.device = Pa_GetDefaultInputDevice();
    if (input_params.device == paNoDevice) {
        fprintf(stderr, "vault: no default input device\n");
        return -1;
    }
    input_params.channelCount = 1;
    input_params.sampleFormat = paInt16;
    input_params.suggestedLatency =
        Pa_GetDeviceInfo(input_params.device)->defaultLowInputLatency;

    err = Pa_OpenStream(&stream, &input_params, NULL,
                         SAMPLE_RATE, FRAMES_PER_BUFFER, paClipOff,
                         NULL, NULL);
    if (err != paNoError) {
        fprintf(stderr, "vault: Pa_OpenStream failed: %s\n",
                Pa_GetErrorText(err));
        return -1;
    }

    err = Pa_StartStream(stream);
    if (err != paNoError) {
        Pa_CloseStream(stream);
        return -1;
    }

    int total_samples = 0;
    int total_needed = SAMPLE_RATE * RECORD_SECONDS;
    if (total_needed > max_samples)
        total_needed = max_samples;

    while (total_samples < total_needed) {
        int to_read = FRAMES_PER_BUFFER;
        if (total_samples + to_read > total_needed)
            to_read = total_needed - total_samples;

        err = Pa_ReadStream(stream, buffer + total_samples, (unsigned long)to_read);
        if (err != paNoError && err != paInputOverflowed)
            break;

        total_samples += to_read;
    }

    Pa_StopStream(stream);
    Pa_CloseStream(stream);

    return total_samples;
}

auth_result_t vault_auth_voice_verify(const vault_config_t *cfg)
{
    if (!cfg->voice_passphrase[0]) {
        fprintf(stderr, "vault: no voice passphrase configured\n");
        return AUTH_ERROR;
    }

    if (!ps_decoder) {
        if (vault_auth_voice_init() != 0)
            return AUTH_ERROR;
    }

    /* Allocate recording buffer */
    int max_samples = SAMPLE_RATE * RECORD_SECONDS;
    int16_t *audio_buf = calloc((size_t)max_samples, sizeof(int16_t));
    if (!audio_buf)
        return AUTH_ERROR;

    vault_tui_status("Speak your passphrase now... (%d seconds)",
                     RECORD_SECONDS);

    int num_samples = record_audio(audio_buf, max_samples);
    if (num_samples <= 0) {
        free(audio_buf);
        vault_tui_status("Failed to record audio");
        return AUTH_ERROR;
    }

    vault_tui_status("Processing speech...");

    /* Run speech recognition */
    int rv = ps_start_utt(ps_decoder);
    if (rv < 0) {
        free(audio_buf);
        return AUTH_ERROR;
    }

    rv = ps_process_raw(ps_decoder, audio_buf, (size_t)num_samples,
                         FALSE, TRUE);
    free(audio_buf);

    if (rv < 0) {
        ps_end_utt(ps_decoder);
        return AUTH_ERROR;
    }

    rv = ps_end_utt(ps_decoder);
    if (rv < 0)
        return AUTH_ERROR;

    /* Get recognized text */
    const char *hypothesis = ps_get_hyp(ps_decoder, NULL);
    if (!hypothesis || strlen(hypothesis) == 0) {
        vault_tui_status("No speech detected");
        return AUTH_FAILURE;
    }

    /* Compare with stored passphrase using fuzzy matching */
    double sim = similarity(hypothesis, cfg->voice_passphrase);

    if (sim >= MATCH_THRESHOLD) {
        return AUTH_SUCCESS;
    }

    return AUTH_FAILURE;
}

#endif /* HAVE_VOICE */
