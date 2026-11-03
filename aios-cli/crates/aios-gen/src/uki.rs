use crate::GenId;

/// Which kernel a UKI boots. Tokens match `loader.conf` (`default aios-gen-*-cachyos*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// The manifest's `kernel.default`.
    Main,
    /// The manifest's `kernel.fallback`.
    Fallback,
}

impl Flavor {
    pub fn token(self) -> &'static str {
        match self {
            Flavor::Main => "cachyos",
            Flavor::Fallback => "lts",
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        match token {
            "cachyos" => Some(Flavor::Main),
            "lts" => Some(Flavor::Fallback),
            _ => None,
        }
    }
}

/// systemd boot-assessment counter: `+LEFT[-DONE]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counter {
    pub left: u32,
    pub done: u32,
}

/// A UKI file name on the ESP: `aios-gen-NNNN-<flavor>[+LEFT[-DONE]].efi`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UkiName {
    pub gen: GenId,
    pub flavor: Flavor,
    pub counter: Option<Counter>,
}

impl UkiName {
    /// Name for a newly built generation: three boot tries.
    pub fn fresh(gen: GenId, flavor: Flavor) -> Self {
        UkiName {
            gen,
            flavor,
            counter: Some(Counter { left: 3, done: 0 }),
        }
    }

    fn base(&self) -> String {
        format!("aios-gen-{}-{}", self.gen, self.flavor.token())
    }

    pub fn file_name(&self) -> String {
        match self.counter {
            None => format!("{}.efi", self.base()),
            Some(Counter { left, done: 0 }) => format!("{}+{left}.efi", self.base()),
            Some(Counter { left, done }) => format!("{}+{left}-{done}.efi", self.base()),
        }
    }

    /// Boot loader entry id: the file name without the counter.
    pub fn entry_id(&self) -> String {
        format!("{}.efi", self.base())
    }

    /// systemd-boot treats an entry with no tries left as bad.
    pub fn is_bad(&self) -> bool {
        matches!(self.counter, Some(Counter { left: 0, .. }))
    }

    pub fn parse(file_name: &str) -> Option<Self> {
        let stem = file_name.strip_suffix(".efi")?;
        let rest = stem.strip_prefix("aios-gen-")?;
        let (gen_str, rest) = rest.split_once('-')?;
        let gen: GenId = gen_str.parse().ok()?;
        let (flavor_str, counter) = match rest.split_once('+') {
            Some((flavor, counter)) => (flavor, Some(parse_counter(counter)?)),
            None => (rest, None),
        };
        let flavor = Flavor::from_token(flavor_str)?;
        Some(UkiName {
            gen,
            flavor,
            counter,
        })
    }
}

fn parse_counter(s: &str) -> Option<Counter> {
    let digits = |v: &str| -> Option<u32> {
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        v.parse().ok()
    };
    match s.split_once('-') {
        Some((left, done)) => Some(Counter {
            left: digits(left)?,
            done: digits(done)?,
        }),
        None => Some(Counter {
            left: digits(s)?,
            done: 0,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GenId;

    #[test]
    fn fresh_name_has_three_tries() {
        let uki = UkiName::fresh(GenId(7), Flavor::Main);
        assert_eq!(uki.file_name(), "aios-gen-0007-cachyos+3.efi");
        assert_eq!(uki.entry_id(), "aios-gen-0007-cachyos.efi");
        assert!(!uki.is_bad());
    }

    #[test]
    fn fallback_flavor_token() {
        let uki = UkiName::fresh(GenId(7), Flavor::Fallback);
        assert_eq!(uki.file_name(), "aios-gen-0007-lts+3.efi");
    }

    #[test]
    fn parse_counted_names() {
        let u = UkiName::parse("aios-gen-0042-cachyos+1-2.efi").unwrap();
        assert_eq!(u.gen, GenId(42));
        assert_eq!(u.flavor, Flavor::Main);
        assert_eq!(u.counter, Some(Counter { left: 1, done: 2 }));
        assert_eq!(u.file_name(), "aios-gen-0042-cachyos+1-2.efi");

        let u = UkiName::parse("aios-gen-0042-lts+3.efi").unwrap();
        assert_eq!(u.counter, Some(Counter { left: 3, done: 0 }));
        assert_eq!(u.file_name(), "aios-gen-0042-lts+3.efi");
    }

    #[test]
    fn parse_blessed_name() {
        let u = UkiName::parse("aios-gen-0042-cachyos.efi").unwrap();
        assert_eq!(u.counter, None);
        assert_eq!(u.file_name(), "aios-gen-0042-cachyos.efi");
        assert!(!u.is_bad());
    }

    #[test]
    fn zero_left_is_bad() {
        let u = UkiName::parse("aios-gen-0042-cachyos+0-3.efi").unwrap();
        assert!(u.is_bad());
        assert_eq!(u.entry_id(), "aios-gen-0042-cachyos.efi");
    }

    #[test]
    fn parse_rejects_foreign_names() {
        for name in [
            "systemd-bootx64.efi",
            "aios-gen-42-cachyos.efi",
            "aios-gen-0042-zen.efi",
            "aios-gen-0042-cachyos+x.efi",
            "aios-gen-0042-cachyos+1-.efi",
            "aios-gen-0042-cachyos",
            "arch-linux.efi",
        ] {
            assert_eq!(UkiName::parse(name), None, "{name} should not parse");
        }
    }
}
