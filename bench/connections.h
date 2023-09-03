#ifndef WOLFSSL_USER_SETTINGS

#include <wolfssl/options.h>

#endif

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#define BENCH_RA
#define BENCH_ECH

#define NUM_BENCHES 100000

#define SERVER_PORT 9000

#define PUBLIC_SERVER_NAME "ech-attestation-server.ch"
#define PRIVATE_SERVER_NAME "ech-attestation-server-private.ch"
#define PRIVATE_SERVER_NAME_LEN strlen(PRIVATE_SERVER_NAME)

#include <unistd.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/coding.h>
#include "attestation.h"
#include <jansson.h>

json_t *timespec_to_json(struct timespec *ts) {
    char s[100];
    char ns[100];
    sprintf(s, "%ld", ts->tv_sec);
    sprintf(ns, "%ld", ts->tv_nsec);

    json_t *json = json_object();
    json_object_set_new(json, "s", json_string(s));
    json_object_set_new(json, "ns", json_string(ns));

    return json;
}

json_t *benchmark_to_json(bool is_server, Benchmark *b) {
    json_t *json = json_object();
    if (is_server) {
        json_object_set_new(json, "server_handshake", timespec_to_json(&b->handshake));
        json_object_set_new(json, "server_hello", timespec_to_json(&b->server_hello));
        json_object_set_new(json, "server_extensions", timespec_to_json(&b->server_extensions));
#ifdef BENCH_RA
        json_object_set_new(json, "server_att_request", timespec_to_json(&b->server_att_request));
        json_object_set_new(json, "server_att_request_generation", timespec_to_json(&b->server_att_request_generation));
        json_object_set_new(json, "server_att_request_challenge_generation", timespec_to_json(&b->server_att_request_challenge_generation));
#endif
    } else {
        json_object_set_new(json, "client_handshake", timespec_to_json(&b->handshake));
        json_object_set_new(json, "client_hello", timespec_to_json(&b->client_hello));
        json_object_set_new(json, "client_extensions", timespec_to_json(&b->client_extensions));
        json_object_set_new(json, "client_certificate_verify", timespec_to_json(&b->client_certificate_verify));
#ifdef BENCH_RA
        json_object_set_new(json, "client_att_request", timespec_to_json(&b->client_att_request));
        json_object_set_new(json, "client_certificate_verify_att_request", timespec_to_json(&b->client_certificate_verify_att_request));
        json_object_set_new(json, "client_certificate_verify_att_request_challenge_generation", timespec_to_json(&b->client_certificate_verify_att_request_challenge_generation));
#endif
    }
    return json;
}

#endif // CONNECTIONS_H
