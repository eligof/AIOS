// Listen on a port, then stay alive.
//
// `listen_probe.c` exits as soon as it has listened, which is all the S2
// scenarios need. A freeze scenario needs the opposite: a process still
// running when the daemon acts on the event it just caused, so the
// quarantine has something to take.
//
// Usage: listen_hold <port> <seconds>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 8899;
    int hold = argc > 2 ? atoi(argv[2]) : 60;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    struct sockaddr_in a;
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    // 0.0.0.0, not loopback: the kernel listen hook returns early for a
    // loopback bind (is_loopback in observe.rs), so a 127.0.0.1 listener
    // emits no event at all.
    a.sin_addr.s_addr = inet_addr("0.0.0.0");
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        perror("bind");
        return 1;
    }
    if (listen(fd, 1) != 0) {
        perror("listen");
        return 1;
    }
    printf("listening on 0.0.0.0:%d\n", port);
    fflush(stdout);
    sleep(hold);
    return 0;
}
