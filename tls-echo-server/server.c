#include <pcap/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wolfssl/ssl.h>

#define PORT 9000
#define BUF_SIZE 1024

int main() {
    // initialize wolfssl
    wolfSSL_Init();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());    // TLS 1.3 fails with SIGSEGV
    if (ctx == NULL) {
        perror("wolfSSL_CTX_new() failure");
        exit(EXIT_FAILURE);
    }

    // load CA certificates
    if (wolfSSL_CTX_load_verify_locations(ctx, "../certs/ca-cert.pem", 0) != SSL_SUCCESS) {
        perror("wolfSSL_CTX_load_verify_locations() failure");
        exit(EXIT_FAILURE);
    }

    // load server certificates
    if (wolfSSL_CTX_use_certificate_file(ctx, "../certs/server-cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        perror("wolfSSL_CTX_use_certificate_file() failed");
        exit(EXIT_FAILURE);
    }

    // load keys
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, "../certs/server-key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        perror("wolfSSL_CTX_use_PrivateKey_file() failed");
        exit(EXIT_FAILURE);
    }

    // create socket
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    /* setsockopt: Eliminates "ERROR on binding: Address already in use" error. */
    int opt = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt() failed");
        exit(EXIT_FAILURE);
    }

    // attach socket to port
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    if (bind(socket_fd, (const struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("bind() failed");
        exit(EXIT_FAILURE);
    }

    // listen to and accept new socket connections
    if (listen(socket_fd, 3) < 0) {
        perror("listen() failed");
        exit(EXIT_FAILURE);
    }

    int conn_fd = accept(socket_fd, (struct sockaddr *) NULL, NULL);

    // create SSL
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        perror("wolfSSL_new() failure");
        exit(EXIT_FAILURE);
    }

    // set wolfssl to use the socket connection
    wolfSSL_set_fd(ssl, conn_fd);

    while (1) {
        char recv_buf[BUF_SIZE] = {0};
        if (wolfSSL_read(ssl, recv_buf, sizeof(recv_buf)) < 0) {
            perror("read() failure");
            exit(EXIT_FAILURE);
        }

        printf("Client: %s", recv_buf);
        if (strcmp(recv_buf, "exit\n") == 0) {
            printf("Exiting...");
            break;
        }

        if (wolfSSL_write(ssl, recv_buf, strlen(recv_buf)) < 0) {
            perror("write() failure");
            exit(EXIT_FAILURE);
        }
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    if (shutdown(socket_fd, SHUT_RDWR) < 0) {
        perror("shutdown() failed");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
