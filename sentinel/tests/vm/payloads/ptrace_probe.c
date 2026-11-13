/* ptrace_probe child | pid N: PTRACE_ATTACH then detach promptly. */
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
static int attach(pid_t p) {
    if (ptrace(PTRACE_ATTACH, p, 0, 0) < 0) return 1;
    int st;
    waitpid(p, &st, 0);
    ptrace(PTRACE_DETACH, p, 0, 0);
    return 0;
}
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "child")) {
        pid_t c = fork();
        if (c == 0) { sleep(30); _exit(0); }
        usleep(100000);
        int r = attach(c);
        kill(c, SIGKILL);
        waitpid(c, 0, 0);
        return r;
    }
    if (!strcmp(argv[1], "pid") && argc > 2) return attach(atoi(argv[2]));
    return 2;
}
