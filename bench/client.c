#include "connections.h"

#include <stdio.h>

int verifyAtt(const ATT_REQUEST *req, const byte *c) {
    return 0;
}

static Benchmark benches[NUM_BENCHES];

int main() {
    //wolfSSL_Debugging_ON();
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

    for (int i = 0; i < NUM_BENCHES; i++) {
        // create socket
        int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd < 0) {
            perror("socket() failed");
            exit(EXIT_FAILURE);
        }
        // create address for connection
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(SERVER_PORT);
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
        wolfSSL_KeepArrays(ssl);
#ifdef BENCH_RA
        ATT_REQUEST req = supported_att_type(i);
        wolfSSL_AttestationRequest(ssl, &req);
        wolfSSL_SetVerifyAttestation(ssl, verifyAtt);
#endif
#ifdef BENCH_ECH
        // read config from 'ech.conf' saved by server
        char *echConfigs64 = NULL;
        size_t len;
        FILE *f = fopen("ech.conf", "r");
        if (!f) {
            perror("fopen() failure");
            exit(EXIT_FAILURE);
        }
        ssize_t echConfigs64Len = getdelim(&echConfigs64, &len, '\0', f);
        if (echConfigs64Len < 0) {
            perror("getdelim() failure");
            exit(EXIT_FAILURE);
        }

        if (wolfSSL_SetEchConfigsBase64(ssl, echConfigs64, echConfigs64Len) != WOLFSSL_SUCCESS) {
            perror("wolfSSL_SetEchConfigsBase64() failure");
            exit(EXIT_FAILURE);
        }
        if (wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, PRIVATE_SERVER_NAME, PRIVATE_SERVER_NAME_LEN) !=
            WOLFSSL_SUCCESS) {
            perror("wolfSSL_UseSNI() failure");
            exit(EXIT_FAILURE);
        }
#endif
        // set wolfssl to use the socket connection
        wolfSSL_set_fd(ssl, socket_fd);

        wolfSSL_connect_TLSv13(ssl);

        benches[i] = *wolfSSL_GetBenchmark(ssl);

        wolfSSL_free(ssl);
        if (close(socket_fd) < 0) {
            perror("close() failed");
            exit(EXIT_FAILURE);
        }
        if ((i + 1) % 100 == 0 || i == NUM_BENCHES - 1) {
            printf("\rRun %d done", i + 1);
            fflush(stdout);
        }

        usleep(1 * 1000);
    }

    printf("\nEncoding benchmarks to json...");
    json_t *array = json_array();
    for (int i = 0; i < NUM_BENCHES; i++) {
        json_array_append(array, benchmark_to_json(FALSE, &benches[i]));
    }
    printf(" DONE\n");

#ifdef BENCH_RA
#ifdef BENCH_ECH
    json_dump_file(array, "client-benchmarks-ra-ech.json", JSON_SORT_KEYS | JSON_INDENT(4));
#else
    json_dump_file(array, "client-benchmarks-ra.json", JSON_SORT_KEYS | JSON_INDENT(4));
#endif
#elifdef BENCH_ECH
    json_dump_file(array, "client-benchmarks-ech.json", JSON_SORT_KEYS | JSON_INDENT(4));
#else
    json_dump_file(array, "client-benchmarks.json", JSON_SORT_KEYS | JSON_INDENT(4));
#endif

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
}