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

    while (1) {
        char send_buf[BUF_SIZE] = {0};
        fgets(send_buf, BUF_SIZE, stdin);

        if (write(socket_fd, send_buf, strlen(send_buf)) < 0) {
            perror("write() failure");
            exit(EXIT_FAILURE);
        }

        if (strcmp(send_buf, "exit\n") == 0) {
            printf("Exiting...");
            break;
        }

        char recv_buf[BUF_SIZE] = {0};
        if (read(socket_fd, recv_buf, sizeof(recv_buf)) < 0) {
            perror("read() failure");
            exit(EXIT_FAILURE);
        }
        printf("Server: %s", recv_buf);
    }

    if (close(socket_fd) < 0) {
        perror("close() failed");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
