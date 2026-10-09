#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }
    int tos = -1;
    socklen_t len = sizeof(tos);
    if (getsockopt(s, IPPROTO_IP, IP_TOS, &tos, &len) < 0) {
        perror("getsockopt IP_TOS");
        close(s);
        return 1;
    }
    close(s);
    printf("%d\n", tos);
    return 0;
}
