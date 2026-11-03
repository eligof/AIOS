//! AIOS generations: ids, subvolume names, UKI file names, metadata and GC policy.

mod gc;
mod id;
mod meta;
mod uki;

pub use gc::gc_select;
pub use id::{gen_from_cmdline, list_complete, next_id, parse_subvol, GenId, SubvolKind, MAX_GEN};
pub use meta::GenerationMeta;
pub use uki::{Counter, Flavor, UkiName};
