#include <pcap/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SERVER_PORT 9000
#define BUF_SIZE 1024

int main() {
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

    while (1) {
        char recv_buf[BUF_SIZE] = {0};
        if (read(conn_fd, recv_buf, sizeof(recv_buf)) < 0) {
            perror("read() failure");
            exit(EXIT_FAILURE);
        }

        printf("Client: %s", recv_buf);
        if (strcmp(recv_buf, "exit\n") == 0) {
            printf("Exiting...");
            break;
        }

        if (write(conn_fd, recv_buf, strlen(recv_buf)) < 0) {
            perror("write() failure");
            exit(EXIT_FAILURE);
        }
    }

    if (shutdown(socket_fd, SHUT_RDWR) < 0) {
        perror("shutdown() failed");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
