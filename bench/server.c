#include "connections.h"


int genAtt(const ATT_REQUEST *req, const byte *challenge, byte *output) {
    //wolfSSL_AttestationRequest_print_ex(stdout, req, TRUE); // is a String currently: ATT_TYPE

//    printf("    Challenge: ");
//    print_hex_arr(challenge, req->challengeSize);
//    printf("\n");
//    printf("generating attestation certificate...");
    create_attestation(output, challenge, req->challengeSize);
//    printf("  DONE\n");
//    printf("  data: ");
//    print_hex_arr(output, SHA_DIGEST_SIZE);
//    printf("\n");

    return SHA_DIGEST_SIZE;
}

static Benchmark benches[NUM_BENCHES];

int main() {
    //wolfSSL_Debugging_ON();
    // initialize wolfssl
    wolfSSL_Init();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL) {
        perror("wolfSSL_CTX_new() failure");
        exit(EXIT_FAILURE);
    }
#ifdef BENCH_ECH
    if (wolfSSL_CTX_GenerateEchConfig(ctx, PUBLIC_SERVER_NAME, 0, 0, 0) != WOLFSSL_SUCCESS) {
        perror("wolfSSL_CTX_GenerateEchConfig() failure");
        exit(EXIT_FAILURE);
    }

    byte echConfig[512];
    word32 echConfigLen = 512;
    char echConfigBase64[512];
    word32 echConfigBase64Len = 512;
    if (wolfSSL_CTX_GetEchConfigs(ctx, echConfig, &echConfigLen) != WOLFSSL_SUCCESS) {
        perror("wolfSSL_CTX_GetEchConfigs() failure");
        exit(EXIT_FAILURE);
    }

    if (Base64_Encode_NoNl(echConfig, echConfigLen, (byte *) echConfigBase64, &echConfigBase64Len) != 0) {
        perror("Base64_Encode_NoNl() failure");
        exit(EXIT_FAILURE);
    }

    FILE *f = fopen("ech.conf", "w");
    if (!f) {
        perror("fopen() failure");
        exit(EXIT_FAILURE);
    }

    fprintf(f, "%s", echConfigBase64);
    fclose(f);

    if (wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, PRIVATE_SERVER_NAME, PRIVATE_SERVER_NAME_LEN) !=
        WOLFSSL_SUCCESS) {
        perror("wolfSSL_CTX_UseSNI() failure");
        exit(EXIT_FAILURE);
    }
#endif
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

    for (int i = 0; i < NUM_BENCHES; i++) {
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
        server_addr.sin_port = htons(SERVER_PORT);
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
        wolfSSL_KeepArrays(ssl);
#ifdef BENCH_RA
        if (wolfSSL_SetGenerateAttestation(ssl, genAtt) != SSL_SUCCESS) {
            perror("wolfSSL_SetGenerateAttestation() failure");
            exit(EXIT_FAILURE);
        }
#endif
        // set wolfssl to use the socket connection
        wolfSSL_set_fd(ssl, conn_fd);
        wolfSSL_accept_TLSv13(ssl);

        benches[i] = *wolfSSL_GetBenchmark(ssl);

        wolfSSL_free(ssl);
        if (shutdown(socket_fd, SHUT_RDWR) < 0) {
            perror("shutdown() failed");
            exit(EXIT_FAILURE);
        }
        if (close(socket_fd) < 0) {
            perror("close() failed");
            exit(EXIT_FAILURE);
        }
        if ((i + 1) % 100 == 0 || i == NUM_BENCHES - 1) {
            printf("\rRun %d done", i + 1);
            fflush(stdout);
        }
    }

    printf("\nEncoding benchmarks to json...");
    json_t *array = json_array();
    for (int i = 0; i < NUM_BENCHES; i++) {
        json_array_append_new(array, benchmark_to_json(TRUE, &benches[i]));
    }
    printf(" DONE\n");

#ifdef BENCH_RA
#ifdef BENCH_ECH
    json_dump_file(array, "server-benchmarks-ra-ech.json", JSON_SORT_KEYS | JSON_INDENT(4));
#else
    json_dump_file(array, "server-benchmarks-ra.json", JSON_SORT_KEYS | JSON_INDENT(4));
#endif
#elifdef BENCH_ECH
    json_dump_file(array, "server-benchmarks-ech.json", JSON_SORT_KEYS | JSON_INDENT(4));
#else
    json_dump_file(array, "server-benchmarks.json", JSON_SORT_KEYS | JSON_INDENT(4));
#endif

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
}
