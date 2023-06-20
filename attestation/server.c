#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/wolfcrypt/sha.h>

#ifndef WOLFSSL_USER_SETTINGS

#include <wolfssl/options.h>

#endif

#include "connections.h"

int genAtt(const ATT_REQUEST *req, const byte *challenge, byte *output) {
    wolfSSL_AttestationRequest_print_ex(stdout, req, TRUE); // is a String currently: ATT_TYPE

    printf("    Challenge: ");
    print_hex_arr(challenge, req->challengeSize);
    printf("\n");
    printf("generating attestation certificate...");
    create_attestation(output, challenge, req->challengeSize);
    printf("  DONE\n");
    printf("  data: ");
    print_hex_arr(output, SHA_DIGEST_SIZE);
    printf("\n");

    return SHA_DIGEST_SIZE;
}

int main() {
    Server *server = server_new(SERVER_PORT);
    if (!server) {
        perror("server_new() failure");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_SetGenerateAttestation(server->ssl, genAtt) != SSL_SUCCESS) {
        perror("wolfSSL_SetGenerateAttestation() failure");
        exit(EXIT_FAILURE);
    }

    if (!server_connect(server)) {
        perror("server_connect() failure");
        exit(EXIT_FAILURE);
    }
    const ATT_REQUEST *req = wolfSSL_GetAttestationRequest(server->ssl);
    if (req == NULL) {
        perror("wolfSSL_GetAttestationRequest() failure");
    }

    while (TRUE) {
        char recv_buf[BUF_SIZE] = {0};
        if (wolfSSL_read(server->ssl, recv_buf, sizeof(recv_buf)) < 0) {
            perror("read() failure");
            exit(EXIT_FAILURE);
        }

        printf("Client: %s", recv_buf);
        if (strcmp(recv_buf, "exit\n") == 0) {
            printf("Exiting...");
            break;
        }

        if (wolfSSL_write(server->ssl, recv_buf, strlen(recv_buf)) <= 0) {
            perror("write() failure");
            exit(EXIT_FAILURE);
        }
    }

    server_teardown(server);
    exit(EXIT_SUCCESS);
}
