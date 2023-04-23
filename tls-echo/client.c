#include <pcap/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#define PORT 9000
#define BUF_SIZE 1024

int main() {
    wolfSSL_Debugging_ON();

    // initialize wolfssl
    wolfSSL_Init();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) {
        perror("wolfSSL_CTX_new() failure");
        exit(EXIT_FAILURE);
    }

    // load CA certificates
    if (wolfSSL_CTX_load_verify_locations(ctx, "../certs/ca-cert.pem", 0) != SSL_SUCCESS) {
        perror("wolfSSL_CTX_load_verify_locations() failure");
        exit(EXIT_FAILURE);
    }

    // create socket
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    // create address for connection
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        perror("inet_pton() failed");
        exit(EXIT_FAILURE);
    }

    if (connect(socket_fd, (const struct sockaddr *) (const struct sockaddr_in *) &addr, sizeof(addr)) < 0) {
        perror("connect() failed");
        exit(EXIT_FAILURE);
    }

    // create SSL
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        perror("wolfSSL_new() failure");
        exit(EXIT_FAILURE);
    }

    unsigned short data = 0xA;
    struct WOLFSSL_EVIDENCE_TYPE evidence;
    evidence.type = WOLFSSL_EVIDENCE_ENC_NUMERIC;
    evidence.credType = WOLFSSL_EVIDENCE_CRED_ATTESTATION;
    evidence.data = (void *) &data;

    struct WOLFSSL_EVIDENCE_TYPE_LIST sup_evidence;
    sup_evidence.evidence = evidence;

    struct WOLFSSL_EVIDENCE_REQ_CLIENT request = {0};
//    request.nonce = 1;
//    request.sup_evidence = &sup_evidence;

    if (wolfSSL_RequestEvidence(ssl, (const void *) &request) != 0) {
        perror("wolfSSL_CTX_RequestEvidence() failure");
        exit(EXIT_FAILURE);
    }

    // set wolfssl to use the socket connection
    wolfSSL_set_fd(ssl, socket_fd);
    wolfSSL_connect(ssl);

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
        perror("close() failed");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
