#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/wolfcrypt/sha.h>

#ifndef WOLFSSL_USER_SETTINGS

#include <wolfssl/options.h>

#endif

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/random.h>

#include "connections.h"

bool provide_RA_verification(WOLFSSL *ssl) {
    WC_RNG rng;
    word64 nonce;
    byte buffer[BUF_SIZE] = {0};
    int num_read;
    word8 ret = ATT_OK;

    printf("generating nonce...");
    // generate nonce
    if (wc_InitRng(&rng) != 0) {
        perror("wc_InitRng() failure");
        return false;
    }
    if (wc_RNG_GenerateBlock(&rng, (byte *) &nonce, sizeof(nonce)) != 0) {
        perror("wc_RNG_GenerateBlock() failure");
        return false;
    }
    printf(" \n");
    printf("  nonce: 0x%lX\n  ", nonce);

    ATT_REQUEST att_request = supported_att_type(nonce);
    wolfSSL_AttestationRequest_print_ex(stdout, &att_request, TRUE);
    byte *send;
    int size;
    if ((size = encode_att(&att_request, &send)) < 0) {
        perror("encode_att(supported att type) failure");
        return false;
    }

    printf("sending supported attestation type...");
    if (wolfSSL_write(ssl, send, size) <= 0) {
        perror("wolfSSL_write(nonce) failure");
        return false;
    }
    printf(" DONE\n");

    printf("receiving verification request...");
    int min_expected_size = sizeof(word64) + sizeof(word16) * 2;
    if ((num_read = wolfSSL_read(ssl, buffer, sizeof(buffer))) < min_expected_size) {
        perror("wolfSSL_read(verifyAtt attestation request) failure");
        return false;
    }
    printf("  DONE\n");
    printf("  request: ");
    print_hex_arr(buffer, num_read);
    printf("\n");

    printf("decoding request...");
    ATT_REQUEST *req;
    byte *challenge;
    if (decode_att_and_c(buffer, num_read, &req, &challenge) != 0) {
        perror("decode_att_and_c() failure");
        ret = ATT_BUF_ERR;
        goto exit;
    }
    printf("  DONE\n");

    printf("  ");
    wolfSSL_AttestationRequest_print(stdout, req);
    printf("    Challenge: ");
    print_hex_arr(challenge, req->challengeSize);
    printf("\n");

    printf("generating verification...");
    byte hash[SHA_DIGEST_SIZE];
    create_attestation(hash, challenge, req->challengeSize);
    printf("  DONE\n");
    printf("  expected Attestation: ");
    print_hex_arr(hash, sizeof(hash));
    printf("\n");

    printf("verifying...");
    if (memcmp(hash, req->data, req->size) != 0) {
        ret = ATT_ERR;
        printf("  FAILED: %d\n", ret);
    } else {
        printf("  DONE: %d\n", ret);
    }

    exit:
    printf("sending verification result...");
    if (wolfSSL_write(ssl, &ret, sizeof(ret)) <= 0) {
        perror("wolfSSL_write(ret) failure");
        return false;
    }
    printf("  DONE\n");

    free(req->data);
    free(req);
    free(challenge);
    return true;
}

int main() {
    Server *verifier = ech_server_new(VERIFIER_PORT, FALSE);
    if (!verifier) {
        perror("server_new() failure");
        exit(EXIT_FAILURE);
    }

    if (!server_connect(verifier)) {
        perror("server_connect() failure");
        exit(EXIT_FAILURE);
    }

    if (!provide_RA_verification(verifier->ssl)) {
        perror("provide_RA_verification() failure");
        exit(EXIT_FAILURE);
    }

    server_teardown(verifier);
    exit(EXIT_SUCCESS);
}
