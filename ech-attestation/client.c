#ifndef WOLFSSL_USER_SETTINGS

#include <wolfssl/options.h>

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CONNECTIONS_H

#include "connections.h"

#endif

Client *client;

int verifyAtt(const ATT_REQUEST *req, const byte *c) {
    byte *att;
    int len;

    printf("verifying:\n  ");
    wolfSSL_AttestationRequest_print(stdout, req);
    printf("    Challenge: ");
    print_hex_arr(c, req->challengeSize);
    printf("\n");

    printf("encoding attestation challenge and challenge...");
    if ((len = encode_att_and_c(req, c, &att)) < 0) {
        perror("encode_att_and_c() failure");
        return len; // is error code
    }
    printf("  DONE\n");
    printf("  data: ");
    print_hex_arr(att, len);
    printf("\n");

    printf("sending to verifier...");
    if (wolfSSL_write(client->verifier, att, len) <= 0) {
        perror("wolfSSL_write(verifier) failure");
        return SSL_FATAL_ERROR;
    }
    printf("  DONE\n");

    printf("reading verification response...");
    byte response;
    if (wolfSSL_read(client->verifier, &response, sizeof(response)) < 0) {
        perror("wolfSSL_read(verifier) failure");
        return SSL_FATAL_ERROR;
    }
    printf("  DONE\n");
    printf("  response: %d\n", response);

    return response;
}

int main() {
    client = client_new();
    if (!client) {
        perror("client_new() failure");
        exit(EXIT_FAILURE);
    }

    ATT_REQUEST *att_request;

    if (!(att_request = client_connect_verifier(client, VERIFIER_PORT))) {
        perror("client_connect_verifier() failure");
        exit(EXIT_FAILURE);
    }

    if (wolfSSL_AttestationRequest(client->server, att_request) != SSL_SUCCESS) {
        perror("wolfSSL_AttestationRequest() failure");
        exit(EXIT_FAILURE);
    }
    if (wolfSSL_SetVerifyAttestation(client->server, verifyAtt) != SSL_SUCCESS) {
        perror("wolfSSL_SetVerifyAttestation() failure");
        exit(EXIT_FAILURE);
    }

    if (!client_connect_server(client, SERVER_PORT)) {
        perror("client_connect_server() failure");
        exit(EXIT_FAILURE);
    }

    const ATT_REQUEST *att_response = wolfSSL_GetAttestationRequest(client->server);
    if (att_response != NULL) {
        wolfSSL_AttestationRequest_print(stdout, att_response);
    } else {
        perror("wolfSSL_GetAttestationRequest() failure");
    }

    while (TRUE) {
        char send_buf[BUF_SIZE] = {0};
        fgets(send_buf, BUF_SIZE, stdin);

        if (wolfSSL_write(client->server, send_buf, (int) strlen(send_buf)) <= 0) {
            perror("wolfSSL_write() failure");
            exit(EXIT_FAILURE);
        }

        if (strcmp(send_buf, "exit\n") == 0) {
            printf("Exiting...");
            break;
        }

        char recv_buf[BUF_SIZE] = {0};
        if (wolfSSL_read(client->server, recv_buf, sizeof(recv_buf)) < 0) {
            perror("wolfSSL_read() failure");
            exit(EXIT_FAILURE);
        }
        printf("Server: %s", recv_buf);
    }

    client_teardown(client);
    exit(EXIT_SUCCESS);
}
