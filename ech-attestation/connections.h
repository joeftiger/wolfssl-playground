// Follows https://github.com/wolfSSL/wolfssl-examples/commit/452ac9e109dcc6074465370aff2f422a314143d2#diff-42e50ab72d489dc766fcd6feced8c87b5062202f68d2789c3d49ae9623974c6c
#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include <string.h>
#include <strings.h>

#ifndef WOLFSSL_USER_SETTINGS

#include <wolfssl/options.h>

#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/coding.h>

#include "attestation.h"

#define SERVER_PORT 9000
#define VERIFIER_PORT 9001
#define BUF_SIZE 16384

#define PUBLIC_SERVER_NAME "ech-attestation-server.ch"
#define PRIVATE_SERVER_NAME "ech-attestation-server-private.ch"
#define PRIVATE_SERVER_NAME_LEN strlen(PRIVATE_SERVER_NAME)

typedef struct Server {
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    int socket_fd;
    int conn_fd;
} Server;

typedef struct Client {
    WOLFSSL_CTX *ctx;
    WOLFSSL *verifier;
    WOLFSSL *server;
    int verifier_fd;
    int server_fd;
} Client;

Server *ech_server_new(uint16_t port, bool is_server) {
    Server *server = malloc(sizeof(Server));
    if (!server) {
        perror("malloc() failure");
        return NULL;
    }

    server->ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!server->ctx) {
        perror("wolfSSL_CTX_new() failure");
        return NULL;
    }

    // use ECH
    if (is_server) {
        if (wolfSSL_CTX_GenerateEchConfig(server->ctx, PUBLIC_SERVER_NAME, 0, 0, 0) != WOLFSSL_SUCCESS) {
            perror("wolfSSL_CTX_GenerateEchConfig() failure");
            return NULL;
        }

        byte echConfig[512];
        word32 echConfigLen = 512;
        char echConfigBase64[512];
        word32 echConfigBase64Len = 512;
        if (wolfSSL_CTX_GetEchConfigs(server->ctx, echConfig, &echConfigLen) != WOLFSSL_SUCCESS) {
            perror("wolfSSL_CTX_GetEchConfigs() failure");
            return NULL;
        }

        if (Base64_Encode_NoNl(echConfig, echConfigLen, (byte *) echConfigBase64, &echConfigBase64Len) != 0) {
            perror("Base64_Encode_NoNl() failure");
            return NULL;
        }

        FILE *f = fopen("ech.conf", "w");
        if (!f) {
            perror("fopen() failure");
            return NULL;
        }

        printf("ECH config: %s\n", echConfigBase64);
        fprintf(f, "%s", echConfigBase64);
        fclose(f);

        if (wolfSSL_CTX_UseSNI(server->ctx, WOLFSSL_SNI_HOST_NAME, PRIVATE_SERVER_NAME, PRIVATE_SERVER_NAME_LEN) !=
            WOLFSSL_SUCCESS) {
            perror("wolfSSL_CTX_UseSNI() failure");
            return NULL;
        }
    }

    // load CA certificates
    if (wolfSSL_CTX_load_verify_locations(server->ctx, "../cert/cert.pem", 0) != SSL_SUCCESS) {
        perror("wolfSSL_CTX_load_verify_locations() failure");
        return NULL;
    }

    // load server certificates
    if (wolfSSL_CTX_use_certificate_file(server->ctx, "../cert/cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        perror("wolfSSL_CTX_use_certificate_file() failure");
        return NULL;
    }

    // load keys
    if (wolfSSL_CTX_use_PrivateKey_file(server->ctx, "../cert/key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        perror("wolfSSL_CTX_use_PrivateKey_file() failure");
        return NULL;
    }

    // create socket
    server->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->socket_fd < 0) {
        perror("socket() failure");
        return NULL;
    }

    /* setsockopt: Eliminates "ERROR on binding: Address already in use" error. */
    int opt = 1;
//    if (setsockopt(server->socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
    if (setsockopt(server->socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt() failure");
        return NULL;
    }

    // attach socket to port
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    if (bind(server->socket_fd, (const struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("bind() failure");
        return NULL;
    }

    server->ssl = wolfSSL_new(server->ctx);
    if (!server->ssl) {
        perror("wolfSSL_new() failure");
        return NULL;
    }
    wolfSSL_KeepArrays(server->ssl);

    return server;
}

bool server_connect(Server *server) {
    // listen to and accept new socket connections
    if (listen(server->socket_fd, 1) < 0) {
        perror("listen() failure");
        return false;
    }

    if ((server->conn_fd = accept(server->socket_fd, (struct sockaddr *) NULL, NULL)) < 0) {
        perror("accept() failure");
        return false;
    }

    // set wolfssl to use the socket connection
    if (wolfSSL_set_fd(server->ssl, server->conn_fd) != SSL_SUCCESS) {
        perror("wolfSSL_set_fd() failure");
        return false;
    }

    if (wolfSSL_accept(server->ssl) != SSL_SUCCESS) {
        perror("wolfSSL_accept() failure");
        return false;
    }

    return true;
}

Client *client_new() {
    Client *client = malloc(sizeof(Client));
    if (!client) {
        perror("malloc() failure");
        return NULL;
    }

    client->ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!client->ctx) {
        perror("wolfSSL_CTX_new() failure");
        return NULL;
    }

    // load CA certificates
    if (wolfSSL_CTX_load_verify_locations(client->ctx, "../cert/cert.pem", 0) != SSL_SUCCESS) {
        perror("wolfSSL_CTX_load_verify_locations() failure");
        return NULL;
    }

    // create ssl for both
    for (int i = 0; i < 2; i++) {
        WOLFSSL **ssl = (i == 0 ? &client->verifier : &client->server);

        // create SSL
        *ssl = wolfSSL_new(client->ctx);
        if (!*ssl) {
            perror("wolfSSL_new() failure");
            return NULL;
        }
        wolfSSL_KeepArrays(*ssl);
    }

    // use ECH for client <-> server connection
    {
        // read config from 'ech.conf' saved by server
        char *echConfigs64 = NULL;
        size_t len;
        FILE *f = fopen("ech.conf", "r");
        if (!f) {
            perror("fopen() failure");
            return NULL;
        }
        ssize_t echConfigs64Len = getdelim(&echConfigs64, &len, '\0', f);
        if (echConfigs64Len < 0) {
            perror("getdelim() failure");
            return NULL;
        }
        printf("ECH config: %s\n", echConfigs64);

        if (wolfSSL_SetEchConfigsBase64(client->server, echConfigs64, echConfigs64Len) != WOLFSSL_SUCCESS) {
            perror("wolfSSL_SetEchConfigsBase64() failure");
            return NULL;
        }
        if (wolfSSL_UseSNI(client->server, WOLFSSL_SNI_HOST_NAME, PRIVATE_SERVER_NAME, PRIVATE_SERVER_NAME_LEN) !=
            WOLFSSL_SUCCESS) {
            perror("wolfSSL_UseSNI() failure");
            return NULL;
        }
    }

    return client;
}

/**
 * Connects a client to a verifier and decodes the first message containing the supported attestation type.
 * @param client    The client to connect
 * @param port      The port of the verifier
 * @return Decoded supported attestation type
 */
ATT_REQUEST *client_connect_verifier(Client *client, uint16_t port) {
    client->verifier_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client->verifier_fd < 0) {
        perror("socket() failure");
        return NULL;
    }

    // create address for connection
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        perror("inet_pton() failure");
        return NULL;
    }

    if (connect(client->verifier_fd, (const struct sockaddr *) (const struct sockaddr_in *) &addr, sizeof(addr)) < 0) {
        perror("connect(verifier) failure");
        return NULL;
    }

    printf("connecting to verifier...");
    // set wolfssl to use the socket connection
    if (wolfSSL_set_fd(client->verifier, client->verifier_fd) != SSL_SUCCESS) {
        perror("wolfSSL_set_fd(verifier) failure");
        return NULL;
    }
    if (wolfSSL_connect(client->verifier) != SSL_SUCCESS) {
        perror("wolfSSL_connect(verifier) failure");
        return NULL;
    }
    printf("  DONE\n");

    printf("receiving supported attestation type...");
    byte buffer[BUF_SIZE];
    int num_read;
    if ((num_read = wolfSSL_read(client->verifier, buffer, sizeof(buffer))) < 0) {
        perror("wolfSSL_read(verifier nonce) failure");
        return NULL;
    }
    printf("  DONE\n");
    printf("  num bytes: %d\n", num_read);

    printf("decoding supported attestation type...");
    ATT_REQUEST *req;
    int err;
    if ((err = decode_att(buffer, num_read, &req)) < 0) {
        printf("FAILED: %d", err);
        perror("decode_att(verifier supported type) failure");
        return NULL;
    }
    printf("  DONE\n");

    return req;
}

bool client_connect_server(Client *client, uint16_t port) {
    client->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client->server_fd < 0) {
        perror("socket() failure");
        return NULL;
    }

    // create address for connection
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        perror("inet_pton() failure");
        return false;
    }

    if (connect(client->server_fd, (const struct sockaddr *) (const struct sockaddr_in *) &addr, sizeof(addr)) < 0) {
        perror("connect(server) failure");
        return NULL;
    }

    // set wolfssl to use the socket connection
    if (wolfSSL_set_fd(client->server, client->server_fd) != SSL_SUCCESS) {
        perror("wolfSSL_set_fd(server) failure");
        return false;
    }
    if (wolfSSL_connect(client->server) != SSL_SUCCESS) {
        perror("wolfSSL_connect(server) failure");
        return false;
    }

    return true;
}

void server_teardown(Server *server) {
    wolfSSL_free(server->ssl);
    wolfSSL_CTX_free(server->ctx);
    wolfSSL_Cleanup();
    close(server->socket_fd);
}

void client_teardown(Client *client) {
    wolfSSL_free(client->verifier);
    wolfSSL_free(client->server);
    wolfSSL_CTX_free(client->ctx);
    wolfSSL_Cleanup();
    close(client->verifier_fd);
    close(client->server_fd);
}

#endif // CONNECTIONS_H
