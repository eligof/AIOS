mod common;

use aios_gen::{gen_from_cmdline, GenId};
use aios_render::cmdline;
use common::{ctx, manifest, manifest_from, MANIFEST};

#[test]
fn full_cmdline_in_spec_order() {
    let expected = "rd.luks.name=0b6c2e7f-5d0a-4c2e-9a71-3f1d2c4b5a69=aios \
root=/dev/mapper/aios \
rootflags=subvol=@root-live,compress=zstd \
rw \
mount.usr=/dev/mapper/aios \
mount.usrflags=subvol=@usr-gen-0007,ro,compress=zstd \
aios.gen=0007 \
init_on_alloc=1 init_on_free=1 slab_nomerge page_alloc.shuffle=1 \
randomize_kstack_offset=on vsyscall=none debugfs=off \
lsm=landlock,lockdown,yama,integrity,apparmor,bpf quiet \
lockdown=integrity \
console=ttyS0,115200\n";
    assert_eq!(cmdline(&manifest(), &ctx()), expected);
}

#[test]
fn lockdown_none_adds_no_lockdown_token() {
    let m = manifest_from(&MANIFEST.replace("lockdown = \"integrity\"", "lockdown = \"none\""));
    let line = cmdline(&m, &ctx());
    assert!(!line.contains("lockdown=integrity"), "got {line}");
    assert!(
        line.ends_with(" quiet console=ttyS0,115200\n"),
        "got {line}"
    );
}

#[test]
fn whitespace_is_normalized_to_single_spaces() {
    let mut c = ctx();
    c.hardening_cmdline = "  quiet\n\tslab_nomerge  \n".to_string();
    let m = manifest_from(&MANIFEST.replace(
        "extra_cmdline = [\"console=ttyS0,115200\"]",
        "extra_cmdline = [\"a=1  b=2\", \"\"]",
    ));
    let line = cmdline(&m, &c);
    assert!(
        line.ends_with(" aios.gen=0007 quiet slab_nomerge lockdown=integrity a=1 b=2\n"),
        "got {line:?}"
    );
    assert!(!line.contains("  "), "double space in {line:?}");
    assert_eq!(line.matches('\n').count(), 1);
}

#[test]
fn generation_drives_usr_subvolume_and_gen_token() {
    let mut c = ctx();
    c.gen = GenId(12);
    let line = cmdline(&manifest(), &c);
    assert!(line.contains(" mount.usrflags=subvol=@usr-gen-0012,ro,compress=zstd "));
    assert_eq!(gen_from_cmdline(&line), Some(GenId(12)));
}
