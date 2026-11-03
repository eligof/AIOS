use aios_gen::GenId;

/// Machine facts the renderers need beyond the manifest. Build it with [`RenderCtx::new`],
/// which validates the values; the fields are public only so tests can write fixtures.
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

impl RenderCtx {
    /// A context whose fields can't add kernel parameters or fstab fields:
    ///
    /// - `luks_uuid`: a canonical UUID (8-4-4-4-12 hex digits).
    /// - `esp_uuid`: a FAT volume id (`XXXX-XXXX` hex) or a canonical UUID.
    /// - `hardening_cmdline`: no `"` and no control characters other than `\n`.
    ///
    /// Hex digits may be either case; values are stored as given.
    pub fn new(
        gen: GenId,
        luks_uuid: &str,
        esp_uuid: &str,
        hardening_cmdline: &str,
    ) -> Result<RenderCtx, String> {
        if !is_uuid(luks_uuid) {
            return Err(format!("invalid LUKS UUID {luks_uuid:?}"));
        }
        if !is_uuid(esp_uuid) && !hex_groups(esp_uuid, &[4, 4]) {
            return Err(format!("invalid ESP volume id {esp_uuid:?}"));
        }
        if hardening_cmdline
            .chars()
            .any(|c| c == '"' || (c.is_control() && c != '\n'))
        {
            return Err(
                "hardening cmdline contains '\"' or a control character other than a newline"
                    .to_string(),
            );
        }
        Ok(RenderCtx {
            gen,
            luks_uuid: luks_uuid.to_string(),
            esp_uuid: esp_uuid.to_string(),
            hardening_cmdline: hardening_cmdline.to_string(),
        })
    }
}

fn is_uuid(s: &str) -> bool {
    hex_groups(s, &[8, 4, 4, 4, 12])
}

/// `s` is groups of hex digits with exactly these lengths, joined by `-`.
fn hex_groups(s: &str, lens: &[usize]) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == lens.len()
        && groups
            .iter()
            .zip(lens)
            .all(|(g, &len)| g.len() == len && g.bytes().all(|b| b.is_ascii_hexdigit()))
}
