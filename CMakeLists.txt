cmake_minimum_required(VERSION 3.24)
project(wolfssl-playground C)

set(CMAKE_C_STANDARD 23)

add_link_options(-harden -pedantic -lwolfssl)

add_executable(echo-server echo-server/server.c)
add_executable(echo-client echo-server/client.c)

add_executable(ssl-echo-server ssl-echo-server/server.c)
add_executable(ssl-echo-client ssl-echo-server/client.c)
