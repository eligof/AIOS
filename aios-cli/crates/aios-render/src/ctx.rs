use aios_gen::GenId;

/// Machine facts the renderers need beyond the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderCtx {
    /// The generation being rendered (`aios.gen=`, `@usr-gen-NNNN`, fstab header).
    pub gen: GenId,
    /// UUID of the LUKS2 partition, for `rd.luks.name=`.
    pub luks_uuid: String,
    /// Volume id of the FAT32 ESP, for the `/efi` fstab line.
    pub esp_uuid: String,
    /// Content of `/usr/lib/aios/cmdline-hardening`: whitespace-separated tokens.
    pub hardening_cmdline: String,
}
