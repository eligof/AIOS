use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

/// Generation number. Displayed zero-padded to 4 digits so lexical order equals numeric order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenId(pub u32);

/// Highest representable generation (4 digits).
pub const MAX_GEN: u32 = 9999;

impl GenId {
    pub fn usr_subvol(self) -> String {
        format!("@usr-gen-{self}")
    }

    pub fn etc_subvol(self) -> String {
        format!("@etc-gen-{self}")
    }
}

impl fmt::Display for GenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}", self.0)
    }
}

impl FromStr for GenId {
    type Err = String;

    /// Accepts exactly four ASCII digits with a value of at least 1.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 4 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("generation id must be 4 digits, got {s:?}"));
        }
        let n: u32 = s
            .parse()
            .map_err(|e| format!("bad generation id {s:?}: {e}"))?;
        if n == 0 {
            return Err("generation id 0000 is not valid".to_string());
        }
        Ok(GenId(n))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubvolKind {
    Usr,
    Etc,
}

/// Parse `@usr-gen-NNNN` / `@etc-gen-NNNN`.
pub fn parse_subvol(name: &str) -> Option<(SubvolKind, GenId)> {
    let (kind, rest) = if let Some(rest) = name.strip_prefix("@usr-gen-") {
        (SubvolKind::Usr, rest)
    } else if let Some(rest) = name.strip_prefix("@etc-gen-") {
        (SubvolKind::Etc, rest)
    } else {
        return None;
    };
    rest.parse().ok().map(|id| (kind, id))
}

/// Generations whose `@usr-gen` and `@etc-gen` subvolumes both exist, ascending.
pub fn list_complete<S: AsRef<str>>(subvols: &[S]) -> Vec<GenId> {
    let mut usr = BTreeSet::new();
    let mut etc = BTreeSet::new();
    for name in subvols {
        match parse_subvol(name.as_ref()) {
            Some((SubvolKind::Usr, id)) => {
                usr.insert(id);
            }
            Some((SubvolKind::Etc, id)) => {
                etc.insert(id);
            }
            None => {}
        }
    }
    usr.intersection(&etc).copied().collect()
}

/// Next generation id (max + 1), or `None` once `MAX_GEN` is used.
pub fn next_id(existing: &[GenId]) -> Option<GenId> {
    let next = existing.iter().map(|g| g.0).max().unwrap_or(0) + 1;
    (next <= MAX_GEN).then_some(GenId(next))
}

/// The generation named by an `aios.gen=NNNN` token on a kernel cmdline.
pub fn gen_from_cmdline(cmdline: &str) -> Option<GenId> {
    cmdline
        .split_whitespace()
        .find_map(|token| token.strip_prefix("aios.gen="))
        .and_then(|value| value.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_zero_padded() {
        assert_eq!(GenId(7).to_string(), "0007");
        assert_eq!(GenId(1234).to_string(), "1234");
    }

    #[test]
    fn subvolume_names() {
        assert_eq!(GenId(7).usr_subvol(), "@usr-gen-0007");
        assert_eq!(GenId(7).etc_subvol(), "@etc-gen-0007");
    }

    #[test]
    fn parse_requires_four_digits_and_nonzero() {
        assert_eq!("0007".parse::<GenId>(), Ok(GenId(7)));
        assert!("7".parse::<GenId>().is_err());
        assert!("00007".parse::<GenId>().is_err());
        assert!("0000".parse::<GenId>().is_err());
        assert!("00a7".parse::<GenId>().is_err());
        assert!("+007".parse::<GenId>().is_err());
    }

    #[test]
    fn parse_subvol_names() {
        assert_eq!(parse_subvol("@usr-gen-0003"), Some((SubvolKind::Usr, GenId(3))));
        assert_eq!(parse_subvol("@etc-gen-0012"), Some((SubvolKind::Etc, GenId(12))));
        assert_eq!(parse_subvol("@usr-cand"), None);
        assert_eq!(parse_subvol("@home"), None);
        assert_eq!(parse_subvol("@usr-gen-12"), None);
    }

    #[test]
    fn list_complete_needs_both_halves() {
        let subvols = [
            "@blank",
            "@usr-gen-0001",
            "@etc-gen-0001",
            "@usr-gen-0002",
            "@etc-gen-0003",
            "@usr-gen-0003",
            "@home",
        ];
        assert_eq!(list_complete(&subvols), vec![GenId(1), GenId(3)]);
    }

    #[test]
    fn next_id_is_max_plus_one() {
        assert_eq!(next_id(&[]), Some(GenId(1)));
        assert_eq!(next_id(&[GenId(1), GenId(5), GenId(3)]), Some(GenId(6)));
        assert_eq!(next_id(&[GenId(MAX_GEN)]), None);
    }

    #[test]
    fn gen_from_cmdline_finds_token() {
        let cmdline = "rd.luks.name=x=aios root=/dev/mapper/aios aios.gen=0042 quiet";
        assert_eq!(gen_from_cmdline(cmdline), Some(GenId(42)));
        assert_eq!(gen_from_cmdline("quiet splash"), None);
        assert_eq!(gen_from_cmdline("aios.gen=42"), None);
        assert_eq!(gen_from_cmdline("xaios.gen=0042"), None);
    }
}
