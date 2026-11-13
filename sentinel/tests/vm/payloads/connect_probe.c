/* connect_probe IP PORT: one non-blocking connect() attempt (may fail; the LSM hook still fires).
 * Exits with errno of the connect (0 if it succeeded) so scenarios can tell EPERM(1) from network errors. */
#include <arpa/inet.h>
#include <errno.h>
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
    int rc = connect(s, (struct sockaddr *)&a, sizeof a);
    int err = rc == 0 ? 0 : errno;
    close(s);
    return err;
}
