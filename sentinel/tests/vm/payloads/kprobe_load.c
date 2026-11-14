/* kprobe_load: one BPF_PROG_LOAD of a trivial kprobe program; exit 0 if loaded, 1 (errno printed) if not. */
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
    struct bpf_insn insn[2];
    memset(insn, 0, sizeof insn);
    insn[0].code = BPF_ALU64 | BPF_MOV | BPF_K; /* r0 = 0 */
    insn[1].code = BPF_JMP | BPF_EXIT;
    union bpf_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.prog_type = BPF_PROG_TYPE_KPROBE;
    attr.insn_cnt = 2;
    attr.insns = (uint64_t)(uintptr_t)insn;
    attr.license = (uint64_t)(uintptr_t)"GPL";
    int fd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof attr);
    if (fd < 0) {
        printf("kprobe_load errno=%d\n", errno);
        return 1;
    }
    close(fd);
    return 0;
}
