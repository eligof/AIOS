/* Copies /bin/true into a memfd and fexecve()s it: a fileless exec. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    int src = open("/bin/true", O_RDONLY);
    if (src < 0) { perror("open"); return 1; }
    int fd = memfd_create("sentinel-test", MFD_CLOEXEC);
    if (fd < 0) { perror("memfd_create"); return 1; }
    char buf[4096];
    ssize_t n;
    while ((n = read(src, buf, sizeof buf)) > 0)
        if (write(fd, buf, n) != n) { perror("write"); return 1; }
    char *argv[] = { "memfd-true", NULL };
    char *envp[] = { NULL };
    fexecve(fd, argv, envp);
    perror("fexecve");
    return 1;
}
