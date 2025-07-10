//! Psycho F4SE
//!
//! This is Psycho F4SE plugin for Fallout 4 game.
//!
//! Why name it "psycho"?
//! We already have bunch of good plugins named with FO4 chems.
//! This plugin is really crazy, so "psycho" fully describes vibe, hehe.
//!
//! Psycho itself tries to be monolitic. The general idea is to backport
//! all IMPORTANT fixes to it. So user can just install one plugin and play,
//! instead of browsing nexusmods or other resources in search of plugins
//! needed to play comfortly.
//!
//! As for now, Psycho will introduce one significant improvement to game -
//! new memory allocator implementation, based on MiMalloc.
//! MiMalloc already showed good results in game development, many of modern
//! games already use it and have zero memory related issues.

mod entry;
mod allocator;
mod logger;