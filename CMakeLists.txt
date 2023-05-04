cmake_minimum_required(VERSION 3.24)
project(wolfssl-playground C)

set(CMAKE_C_STANDARD 23)

find_library(WOLFSSL_LIB wolfssl /usr/local/lib/)
link_libraries(debug "${WOLFSSL_LIB}")

add_link_options(-pedantic -lwolfssl)

add_executable(echo-server echo/server.c)
add_executable(echo-client echo/client.c)

add_executable(tls-server tls-echo/server.c)
add_executable(tls-client tls-echo/client.c)

add_executable(attestation-server attestation/server.c)
add_executable(attestation-client attestation/client.c)
