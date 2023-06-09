#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS

#include <wolfssl/options.h>

#endif

#include <wolfssl/ssl.h>

enum {
    ATT_OK = 0,
    ATT_ERR = 1,
    ATT_BUF_ERR = 2,
};

static const word16 CHALLENGE_SIZE = 8;
static unsigned char ATT_TYPE[] = "Test";
static unsigned char ATT_DATA[] = "Hello Attestation";

const int i0 = sizeof(word64);      // .nonce (.challengeSize next)
const int i1 = i0 + sizeof(word16); // .challengeSize (.size next)) NOLINT(cppcoreguidelines-narrowing-conversions)
const int i2 = i1 + sizeof(word16); // .size (.data next)           NOLINT(cppcoreguidelines-narrowing-conversions)

void print_hex_arr(const byte *arr, int len) {
    printf("0x");
    for (int i = 0; i < len; i++) {
        printf("%X", arr[i]);
    }
}

ATT_REQUEST supported_att_type(word64 nonce) {
    ATT_REQUEST req = {
            .nonce = nonce,
            .challengeSize = CHALLENGE_SIZE,
            .size = sizeof(ATT_TYPE),
            .data = ATT_TYPE,
    };

    return req;
}

/**
 * Creates a Sha hash of the challenge and ATT_DATA.
 * The buffer should be big enough to hold SHA_DIGEST_SIZE bytes.
 *
 * @param buf       The buffer to write to
 * @param challenge The challenge to hash
 * @param size      The size of the challenge
 */
void create_attestation(byte *buf, const byte *challenge, const int size) {
    Sha sha;
    wc_InitSha(&sha);
    wc_ShaUpdate(&sha, challenge, size);
    wc_ShaUpdate(&sha, ATT_DATA, sizeof(ATT_DATA));
    wc_ShaFinal(&sha, buf);
}

int encode_att(const ATT_REQUEST *req, byte **buffer) {
    int total = i2 + req->size;     // .data >..

    *buffer = malloc(total);
    if (!*buffer) {
        return MEMORY_E;
    }

    byte *buf = *buffer;

    memcpy(&buf[0], &req->nonce, sizeof(word64));
    memcpy(&buf[i0], &req->challengeSize, sizeof(word16));
    memcpy(&buf[i1], &req->size, sizeof(word16));
    memcpy(&buf[i2], req->data, req->size);

    return total;
}

/**
 * Encodes an attestation request and a challenge into a byte buffer.
 * @param req   The attestation request to encode
 * @param c     The challenge to encode
 * @param buf   The buffer allocate and write to
 * @return number of bytes written. Negative if error
 */
int encode_att_and_c(const ATT_REQUEST *req, const byte *c, byte **buffer) {
    int i3 = i2 + req->size;                // .data (challenge next)
    int total = i3 + req->challengeSize;    // challenge (total)

    *buffer = malloc(total);
    if (!*buffer) {
        return MEMORY_E;
    }
    byte *buf = *buffer;

    memcpy(&buf[0], &req->nonce, sizeof(word64));
    memcpy(&buf[i0], &req->challengeSize, sizeof(word16));
    memcpy(&buf[i1], &req->size, sizeof(word16));
    memcpy(&buf[i2], req->data, req->size);
    memcpy(&buf[i3], c, req->challengeSize);

    return total;
}

/**
 * Decodes an attestation request from a buffer.
 * @param buffer        The buffer to decode
 * @param max_length    The maximum length of contained request
 * @param req           The pointer to store decoded request at
 * @return number of bytes read, negative if error
 */
int decode_att(const byte *buffer, unsigned long max_length, ATT_REQUEST **req) {
    if (max_length < i2) {
        perror("max_length < i2");
        return BUFFER_E;
    }

    *req = malloc(sizeof(ATT_REQUEST));
    if (!*req) {
        perror("!*req");
        return MEMORY_E;
    }
    ATT_REQUEST *r = *req;

    r->is_request = FALSE;
    memcpy(&r->nonce, &buffer[0], sizeof(word64));
    memcpy(&r->challengeSize, &buffer[i0], sizeof(word16));
    memcpy(&r->size, &buffer[i1], sizeof(word16));
    int total = i2 + r->size;                // .data >..
    if (total > max_length) {
        perror("total > max_length");
        return BUFFER_E;
    }

    r->data = malloc(r->size);
    if (!r->data) {
        perror("!req->data");
        return MEMORY_E;
    }
    memcpy(r->data, &buffer[i2], r->size);

    return total;
}

/**
 * Decodes an ATT_REQUEST and a challenge from a byte buffer.
 *
 * @param buffer    The buffer to parse
 * @param buf_len   The length of the buffer
 * @param req       The pointer to store parsed request at
 * @param c         The pointer to store parsed challenge at
 * @return 0 on success
 */
int decode_att_and_c(const byte *buffer, unsigned long buf_len, ATT_REQUEST **req, byte **c) {
    if (buf_len < i2) {
        perror("buf_len < i2\n");
        return BUFFER_E;
    }

    *req = malloc(sizeof(ATT_REQUEST));
    if (!*req) {
        perror("!*req\n");
        return MEMORY_E;
    }
    ATT_REQUEST *r = *req;

    r->is_request = FALSE;
    memcpy(&r->nonce, &buffer[0], sizeof(word64));
    memcpy(&r->challengeSize, &buffer[i0], sizeof(word16));
    memcpy(&r->size, &buffer[i1], sizeof(word16));
    unsigned long i3 = i2 + r->size;                // .data (challenge next)
    unsigned long total = i3 + r->challengeSize;    // challenge (total)
    if (buf_len != total) {
        perror("buf_len != total");
        return BUFFER_E;
    }

    r->data = malloc(r->size);
    if (!r->data) {
        perror("!req->data");
        return MEMORY_E;
    }
    memcpy(r->data, &buffer[i2], r->size);

    *c = malloc(r->challengeSize);
    if (!*c) {
        perror("!*c");
        return MEMORY_E;
    }
    memcpy(*c, &buffer[i3], r->challengeSize);

    return 0;
}

