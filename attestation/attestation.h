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


static unsigned char ATT_TYPE[] = "Test";
static unsigned char ATT_DATA[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
static ATT_REQUEST ATT_REQ = {.challengeSize = 8, .typeSize = sizeof(ATT_TYPE), .type = ATT_TYPE, .dataSize = sizeof(ATT_DATA), .data = ATT_DATA};

void print_hex_arr(const byte *arr, int len) {
    printf("0x");
    for (int i = 0; i < len; i++) {
        printf("%X", arr[i]);
    }
}

int generateAttestation(const ATT_REQUEST *req, const byte *c, word16 cLen, byte *output) {
    printf("entering generateAttestation(): %d bytes\n", req->dataSize + cLen);

    printf("  Data:        ");
    print_hex_arr(req->data, req->dataSize);
    printf("\n");
    printf("  Challenge:   ");
    print_hex_arr(c, cLen);
    printf("\n");

    memcpy(output, req->data, req->dataSize);
    memcpy(&output[req->dataSize], c, cLen);

    printf("  Attestation: ");
    print_hex_arr(output, req->dataSize + cLen);
    printf("\n");

    return req->dataSize + cLen;
}

int verifyAttestation(const ATT_REQUEST *req, const byte *c, word16 cLen) {
    printf("entering verifyAttestation(): %d bytes\n", req->dataSize);

    printf("  Data:        ");
    print_hex_arr(req->data, req->dataSize);
    printf("\n");
    printf("  Challenge:   ");
    print_hex_arr(c, cLen);
    printf("\n");

    if (memcmp(req->data, ATT_DATA, sizeof(ATT_DATA)) != 0) {
        printf("-1\n");
        return -1;
    }
    if (memcmp(&req->data[sizeof(ATT_DATA)], c, cLen) != 0) {
        printf("-2\n");
        return -2;
    }
    printf("0\n");
    return 0;
}

