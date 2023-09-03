cmake_minimum_required(VERSION 3.24)
project(wolfssl-playground C)

set(CMAKE_C_STANDARD 23)

find_library(WOLFSSL_LIB wolfssl "/usr/local/lib/")
#link_libraries(debug "${WOLFSSL_LIB}")
link_libraries(optimized "${WOLFSSL_LIB}")

add_link_options(
        -pedantic
        -lwolfssl
        -ljansson
        -fpie -pie
        -fstack-protector-all
        -Wformat -Wformat-security -Werror=format-security -Werror
)

add_executable(echo-server echo/server.c)
add_executable(echo-client echo/client.c)

add_executable(tls-server tls-echo/server.c)
add_executable(tls-client tls-echo/client.c)

add_executable(attestation-server attestation/server.c attestation/attestation.h attestation/connections.h)
add_executable(attestation-client attestation/client.c attestation/attestation.h attestation/connections.h)
add_executable(attestation-verifier attestation/verifier.c attestation/attestation.h attestation/connections.h)

add_executable(ech-attestation-server ech-attestation/server.c ech-attestation/attestation.h ech-attestation/connections.h)
add_executable(ech-attestation-client ech-attestation/client.c ech-attestation/attestation.h ech-attestation/connections.h)
add_executable(ech-attestation-verifier ech-attestation/verifier.c ech-attestation/attestation.h ech-attestation/connections.h)

add_executable(bench-server bench/server.c bench/attestation.h bench/connections.h)
add_executable(bench-client bench/client.c bench/attestation.h bench/connections.h)

add_custom_target(echo DEPENDS echo-server echo-client)
add_custom_target(tls-echo DEPENDS tls-server tls-client)
add_custom_target(attestation DEPENDS attestation-server attestation-client attestation-verifier)
add_custom_target(ech-attestation DEPENDS ech-attestation-server ech-attestation-client ech-attestation-verifier)