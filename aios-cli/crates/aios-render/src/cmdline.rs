use crate::RenderCtx;
use aios_manifest::{Lockdown, Manifest};

/// Kernel command line baked into every UKI (`/etc/kernel/cmdline`, spec §3 step 3).
///
/// One line: the AIOS root/usr tokens, the hardening tokens, `lockdown=integrity` when
/// enabled, then `kernel.extra_cmdline`. Tokens are joined by single spaces.
pub fn cmdline(m: &Manifest, ctx: &RenderCtx) -> String {
    let gen = ctx.gen;
    let mut tokens: Vec<String> = vec![
        format!("rd.luks.name={}=aios", ctx.luks_uuid),
        "root=/dev/mapper/aios".to_string(),
        "rootflags=subvol=@root-live,compress=zstd".to_string(),
        "rw".to_string(),
        "mount.usr=/dev/mapper/aios".to_string(),
        format!(
            "mount.usrflags=subvol={},ro,compress=zstd",
            gen.usr_subvol()
        ),
        format!("aios.gen={gen}"),
    ];
    tokens.extend(ctx.hardening_cmdline.split_whitespace().map(str::to_string));
    if m.kernel.lockdown == Lockdown::Integrity {
        tokens.push("lockdown=integrity".to_string());
    }
    tokens.extend(
        m.kernel
            .extra_cmdline
            .iter()
            .flat_map(|entry| entry.split_whitespace())
            .map(str::to_string),
    );
    format!("{}\n", tokens.join(" "))
}
