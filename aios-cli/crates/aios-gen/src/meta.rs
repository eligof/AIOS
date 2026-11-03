use crate::GenId;
use serde::{Deserialize, Serialize};

/// Contents of `/etc/aios/generation.toml` inside each `@etc-gen-NNNN` (spec §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationMeta {
    pub id: u32,
    /// Parent generation id, 0 for gen-1.
    pub parent: u32,
    /// RFC 3339 UTC timestamp, e.g. `2026-11-03T21:14:05Z`.
    pub created: String,
    /// Git commit of the manifest repo that produced this generation.
    pub manifest_commit: String,
    /// `"<package> <version>"` for each kernel in the generation.
    pub kernels: Vec<String>,
    /// sha256 (hex) of the sorted `pacman -Qq` output.
    pub package_set_sha256: String,
}

impl GenerationMeta {
    pub fn gen_id(&self) -> GenId {
        GenId(self.id)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string(self).expect("GenerationMeta contains only TOML-representable fields")
    }

    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GenerationMeta {
        GenerationMeta {
            id: 7,
            parent: 6,
            created: "2026-11-03T21:14:05Z".to_string(),
            manifest_commit: "3f9c2a1".to_string(),
            kernels: vec![
                "linux-cachyos 7.3.0-4".to_string(),
                "linux-cachyos-lts 6.18.55-2".to_string(),
            ],
            package_set_sha256: "ab".repeat(32),
        }
    }

    #[test]
    fn round_trips_through_toml() {
        let meta = sample();
        let text = meta.to_toml();
        assert!(text.contains("id = 7"));
        assert!(text.contains("created = \"2026-11-03T21:14:05Z\""));
        assert_eq!(GenerationMeta::from_toml(&text).unwrap(), meta);
    }

    #[test]
    fn rejects_unknown_fields() {
        let text = format!("{}extra = 1\n", sample().to_toml());
        assert!(GenerationMeta::from_toml(&text).is_err());
    }

    #[test]
    fn gen_id_accessor() {
        assert_eq!(sample().gen_id(), crate::GenId(7));
    }
}
