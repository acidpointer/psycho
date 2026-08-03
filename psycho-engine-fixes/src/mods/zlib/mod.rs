//! Verified zlib decompression replacement for Fallout: New Vegas.
//!
//! Complete TES records use a fallibly allocated, thread-local libdeflate
//! decoder. BSA streams try that same complete-buffer path only when the native
//! buffer capacity proves it can succeed; otherwise they lazily initialize
//! zlib-rs state directly in the engine `z_stream`. Per-stream state preserves
//! continuation across interleaved archives and sequential IO-worker handoffs.
//!
//! Installation is an all-or-nothing transaction over the complete runtime
//! callsite set and rejects any executable whose calls no longer target the
//! audited stock zlib functions. GECK is deliberately outside this module's
//! supported surface until an exact editor executable and its independently
//! versioned callsites are available for static proof.
//!
//! See `docs/zlib_stream_ownership.md` for the executable callsites, ownership
//! proof, FastDecompress comparison, compatibility limits, and validation plan.

mod r#impl;

pub use r#impl::*;
