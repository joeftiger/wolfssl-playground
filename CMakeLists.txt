cmake_minimum_required(VERSION 3.24)
project(wolfssl-playground C)

set(CMAKE_C_STANDARD 23)

find_library(WOLFSSL_LIB wolfssl /usr/local/lib/)

add_link_options(-harden -pedantic -lwolfssl)

add_executable(echo-server echo-server/server.c)
add_executable(echo-client echo-server/client.c)

add_executable(tls-echo-server tls-echo-server/server.c)
add_executable(ssl-echo-client tls-echo-server/client.c)
target_link_libraries(tls-echo-server PRIVATE "${WOLFSSL_LIB}")
target_link_libraries(ssl-echo-client PRIVATE "${WOLFSSL_LIB}")
