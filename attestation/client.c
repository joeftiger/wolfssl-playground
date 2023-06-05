#include <pcap/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "attestation.h"

#define PORT 9000
#define BUF_SIZE 1024

int main() {
//    wolfSSL_Debugging_ON();
    int ret;

    // initialize wolfssl
    wolfSSL_Init();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) {
        perror("wolfSSL_CTX_new() failure");
        exit(EXIT_FAILURE);
    }

    // load CA certificates
    if ((ret = wolfSSL_CTX_load_verify_locations(ctx, "../cert/cert.pem", 0)) != SSL_SUCCESS) {
        perror("wolfSSL_CTX_load_verify_locations() failure");
        printf("error value: %d", ret);
        exit(EXIT_FAILURE);
    }

    // create socket
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("socket() failure");
        exit(EXIT_FAILURE);
    }

    // create address for connection
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    // Convert IPv4 and IPv6 addresses from text to binary form
    if ((ret = inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr)) != 1) {
        perror("inet_pton() failure");
        printf("error value: %d", ret);
        exit(EXIT_FAILURE);
    }

    if ((ret = connect(socket_fd, (const struct sockaddr *) (const struct sockaddr_in *) &addr, sizeof(addr))) < 0) {
        perror("connect() failure");
        printf("error value: %d", ret);
        exit(EXIT_FAILURE);
    }

    // create SSL
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        perror("wolfSSL_new() failure");
        exit(EXIT_FAILURE);
    }
    wolfSSL_KeepArrays(ssl);

    if (wolfSSL_SetVerifyAttestation(ssl, verifyAttestation) != SSL_SUCCESS) {
        perror("wolfSSL_SetVerifyAttestation() failure");
        exit(EXIT_FAILURE);
    }

    if ((ret = wolfSSL_AttestationRequest(ssl, &ATT_REQ)) != SSL_SUCCESS) {
        perror("wolfSSL_AttestationRequest() failure");
        printf("error value: %d", ret);
        exit(EXIT_FAILURE);
    }

    // set wolfssl to use the socket connection
    if ((ret = wolfSSL_set_fd(ssl, socket_fd)) != SSL_SUCCESS) {
        perror("wolfSSL_set_fd() failure");
        printf("error value: %d", ret);
        exit(EXIT_FAILURE);
    }
    if ((ret = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
        perror("wolfSSL_connect() failure");
        printf("error value: %d", ret);
        exit(EXIT_FAILURE);
    }

    const ATT_REQUEST *req = wolfSSL_GetAttestationRequest(ssl);
    if (req == NULL) {
        perror("wolfSSL_GetAttestationRequest() failure");
//        exit(EXIT_FAILURE);
    } else {
        wolfSSL_AttestationRequest_print_ex(stdout, req, TRUE);
    }

    while (1) {
        char send_buf[BUF_SIZE] = {0};
        fgets(send_buf, BUF_SIZE, stdin);

        if (wolfSSL_write(ssl, send_buf, (int) strlen(send_buf)) < 0) {
            perror("wolfSSL_write() failure");
            exit(EXIT_FAILURE);
        }

        if (strcmp(send_buf, "exit\n") == 0) {
            printf("Exiting...");
            break;
        }

        char recv_buf[BUF_SIZE] = {0};
        if (wolfSSL_read(ssl, recv_buf, sizeof(recv_buf)) < 0) {
            perror("wolfSSL_read() failure");
            exit(EXIT_FAILURE);
        }
        printf("Server: %s", recv_buf);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    if (close(socket_fd) < 0) {
        perror("close() failure");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
