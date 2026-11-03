//! Pure renderers for the files AIOS writes into a generation's `/etc`.
//!
//! Nothing here touches the system: every function maps a manifest (plus a
//! [`RenderCtx`]) to text.

mod cmdline;
mod ctx;

pub use cmdline::cmdline;
pub use ctx::RenderCtx;
