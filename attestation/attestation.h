//
// Created by julius on 24/05/23.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS

#include <wolfssl/options.h>

#endif

#include <wolfssl/ssl.h>


static const word16 CHALLENGE_SIZE = 8;
static const word64 NONCE = 0xFEDCBA9876543210;
static unsigned char TYPE[] = "Test";
static unsigned char DATA[] = "Hello Attestation";

static const ATT_REQUEST ATT_REQ = {.nonce = NONCE, .challengeSize = CHALLENGE_SIZE, .size = sizeof(TYPE), .data = TYPE};
static const ATT_REQUEST ATT_RESP = {.nonce = NONCE, .challengeSize = CHALLENGE_SIZE, .size = sizeof(DATA), .data = DATA};

void print_hex_arr(const byte *arr, int len) {
    printf("0x");
    for (int i = 0; i < len; i++) {
        printf("%X", arr[i]);
    }
}

int generateAttestation(const ATT_REQUEST *req, const byte *c, word16 cLen, byte *output) {
    printf("entering generateAttestation(): %d bytes\n", req->size + cLen);

    printf("  Type:        ");
    print_hex_arr(req->data, req->size);
    printf("\n");
    printf("  Challenge:   ");
    print_hex_arr(c, cLen);
    printf("\n");

    memcpy(output, req->data, req->size);
    memcpy(&output[req->size], c, cLen);

    printf("  Attestation: ");
    print_hex_arr(output, req->size + cLen);
    printf("\n");

    return req->size + cLen;
}

int verifyAttestation(const ATT_REQUEST *req, const byte *c, word16 cLen) {
    printf("entering verifyAttestation(): %d bytes\n", req->size);

    printf("  Challenge:   ");
    print_hex_arr(c, cLen);
    printf("\n");
    printf("  Data:        ");
    print_hex_arr(req->data, req->size);
    printf("\n");

    // FIXME: Returns -1
    printf("  Result:      ");
    if (memcmp(req->data, DATA, sizeof(DATA)) != 0) {
        printf("-1\n");
        return -1;
    }
    if (memcmp(&req->data[sizeof(DATA)], c, cLen) != 0) {
        printf("-2\n");
        return -2;
    }
    printf("0\n");
    return 0;
}

