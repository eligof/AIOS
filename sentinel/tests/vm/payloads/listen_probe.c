/* listen_probe IP PORT: socket+bind+listen, then hold briefly. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[2]))};
    inet_pton(AF_INET, argv[1], &a.sin_addr);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) return 3;
    if (listen(s, 4) < 0) return 4;
    usleep(300000);
    close(s);
    return 0;
}
