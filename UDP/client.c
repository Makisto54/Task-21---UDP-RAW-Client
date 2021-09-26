#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/ip.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUF_SIZE 255
#define DEST_PORT 0xAABB
#define SOURCE_PORT 0xBBAA
#define SERVER_ADDR "127.0.0.1"

void error_macro(const char *error)
{
    perror(error);
    exit(1);
}

int main(void)
{
    int address = 0;
    char *ptr = NULL;
    int socket_fd = 0;
    struct udphdr *udp = {0};
    char buf[BUF_SIZE] = {0};
    struct sockaddr_in client = {0};
    struct sockaddr_in server = {0};
    char msg_buf[BUF_SIZE - 8] = {0};
    socklen_t client_socket_fd_size = 0;

    socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (socket_fd == -1)
    {
        error_macro("SOCKET CREATE");
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(DEST_PORT);
    int ret = inet_pton(AF_INET, SERVER_ADDR, &address);
    if (ret == -1 || ret == 0)
    {
        error_macro("INET PTON");
    }
    server.sin_addr.s_addr = address;

    client_socket_fd_size = sizeof(struct sockaddr_in);

    do
    {
        ptr = buf;
        bzero(buf, BUF_SIZE);
        bzero(msg_buf, BUF_SIZE - 8);

        udp = (struct udphdr*)buf;

        udp->source = htons(SOURCE_PORT);
        udp->dest = htons(DEST_PORT);
        udp->len = htons(BUF_SIZE);
        udp->check = 0;

        ptr += 8;

        fgets(msg_buf, BUF_SIZE - 8, stdin);
        char *p = strchr(msg_buf, '\n');
        if (p != NULL)
        {
            msg_buf[strlen(msg_buf) - 1] = '\0';
        }
        memcpy(ptr, msg_buf, BUF_SIZE - 8);

        if (sendto(socket_fd, buf, BUF_SIZE, 0, (struct sockaddr *)&server,
            client_socket_fd_size) == -1)
        {
            error_macro("SEND ERROR");
        }

        for (;;)
        {
            if (recvfrom(socket_fd, buf, BUF_SIZE, 0, (struct sockaddr *)&client,
                &client_socket_fd_size) == -1)
            {
                error_macro("RECVFROM ERROR");
            }

            udp = (struct udphdr*)(buf + sizeof(struct iphdr));
            if (ntohs(udp->dest) == SOURCE_PORT)
            {
                printf("Received Message - %s\n", (buf + sizeof(struct udphdr) + sizeof(struct iphdr)));
                break;
            }
        }
    } while (strncmp((buf + sizeof(struct udphdr) + sizeof(struct iphdr)), "exit", BUF_SIZE) != 0);

    return 0;
}
