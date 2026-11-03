//! AIOS generations: ids, subvolume names, UKI file names, metadata and GC policy.

mod id;

pub use id::{gen_from_cmdline, list_complete, next_id, parse_subvol, GenId, SubvolKind, MAX_GEN};
