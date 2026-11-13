/* connect_probe IP PORT: one non-blocking connect() attempt (may fail; the LSM hook still fires). */
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    fcntl(s, F_SETFL, O_NONBLOCK);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[2]))};
    inet_pton(AF_INET, argv[1], &a.sin_addr);
    connect(s, (struct sockaddr *)&a, sizeof a);
    close(s);
    return 0;
}
