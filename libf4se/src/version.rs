//! Runtime version constants
//! Ported from original F4SE project.

use libpsycho::common::exe_version::make_exe_version;

// Runtime version constants

/// `0x010101D0` initial version released on steam
pub const RUNTIME_VERSION_1_1_29: u32 = make_exe_version(1, 1, 29);

/// `0x010101E0` day1 patch to fix xaudio problem
pub const RUNTIME_VERSION_1_1_30: u32 = make_exe_version(1, 1, 30);

/// `0x01020210` beta, removed mini-mod-manager from the launcher
pub const RUNTIME_VERSION_1_2: u32 = make_exe_version(1, 2, 33);

/// `0x01020250` beta - unclear
pub const RUNTIME_VERSION_1_2_37: u32 = make_exe_version(1, 2, 37);

/// `0x010302D0` beta - compiled with optimization enabled (finally), added hbao+ and cuda-based impact particles (shame)
pub const RUNTIME_VERSION_1_3_45: u32 = make_exe_version(1, 3, 45);

/// `0x010302F0` release, originally pushed as beta
pub const RUNTIME_VERSION_1_3_47: u32 = make_exe_version(1, 3, 47);

/// `0x010407C0` beta - preliminary internal mod manager
pub const RUNTIME_VERSION_1_4_124: u32 = make_exe_version(1, 4, 124);

/// `0x010407D0` beta - released same day as previous version. about 300K smaller
pub const RUNTIME_VERSION_1_4_125: u32 = make_exe_version(1, 4, 125);

/// `0x01040830` beta -
pub const RUNTIME_VERSION_1_4_131: u32 = make_exe_version(1, 4, 131);

/// `0x01040840` released without a beta version
pub const RUNTIME_VERSION_1_4_132: u32 = make_exe_version(1, 4, 132);

/// `0x010508D0` beta - survival mode improvements
pub const RUNTIME_VERSION_1_5_141: u32 = make_exe_version(1, 5, 141);

/// `0x01050930` beta - survival mode improvements
pub const RUNTIME_VERSION_1_5_147: u32 = make_exe_version(1, 5, 147);

/// `0x01050970` beta - survival mode improvements
pub const RUNTIME_VERSION_1_5_151: u32 = make_exe_version(1, 5, 151);

/// `0x010509A0` beta - public editor beta
pub const RUNTIME_VERSION_1_5_154: u32 = make_exe_version(1, 5, 154);

/// `0x010509D0` beta - released the same day
pub const RUNTIME_VERSION_1_5_157: u32 = make_exe_version(1, 5, 157);

/// `0x01050CD0` beta - released to main
pub const RUNTIME_VERSION_1_5_205: u32 = make_exe_version(1, 5, 205);

/// `0x01050D20` beta - no whatsnew
pub const RUNTIME_VERSION_1_5_210: u32 = make_exe_version(1, 5, 210);

/// `0x01051330` release - exe almost identical
pub const RUNTIME_VERSION_1_5_307: u32 = make_exe_version(1, 5, 307);

/// `0x010519C0` beta - that's a big number. added GetOrbisModInfo console cmd (does nothing)
pub const RUNTIME_VERSION_1_5_412: u32 = make_exe_version(1, 5, 412);

/// `0x010519E0` beta - why so many releases all at once
pub const RUNTIME_VERSION_1_5_414: u32 = make_exe_version(1, 5, 414);

/// `0x01051A00` release - why so many releases all at once
pub const RUNTIME_VERSION_1_5_416: u32 = make_exe_version(1, 5, 416);

/// `0x01060000` beta
pub const RUNTIME_VERSION_1_6_0: u32 = make_exe_version(1, 6, 0);

/// `0x01060030` beta - promoted to release
pub const RUNTIME_VERSION_1_6_3: u32 = make_exe_version(1, 6, 3);

/// `0x01060090` release - no interim beta
pub const RUNTIME_VERSION_1_6_9: u32 = make_exe_version(1, 6, 9);

/// `0x01070070` beta
pub const RUNTIME_VERSION_1_7_7: u32 = make_exe_version(1, 7, 7);

/// `0x01070090` beta - promoted to release
pub const RUNTIME_VERSION_1_7_9: u32 = make_exe_version(1, 7, 9);

/// `0x010700A0` release - no interim beta
pub const RUNTIME_VERSION_1_7_10: u32 = make_exe_version(1, 7, 10);

/// `0x010700C0` release - no interim beta, wtf bethesda
pub const RUNTIME_VERSION_1_7_12: u32 = make_exe_version(1, 7, 12);

/// `0x010700F0` release - no interim beta, released on a holiday weekend, wtf bethesda
pub const RUNTIME_VERSION_1_7_15: u32 = make_exe_version(1, 7, 15);

/// `0x01070130` release - rolled back
pub const RUNTIME_VERSION_1_7_19: u32 = make_exe_version(1, 7, 19);

/// `0x01070160` release - bugfix for 1.7.19
pub const RUNTIME_VERSION_1_7_22: u32 = make_exe_version(1, 7, 22);

/// `0x01080070` release - poking at the built-in mod manager
pub const RUNTIME_VERSION_1_8_7: u32 = make_exe_version(1, 8, 7);

/// `0x01090040` release - high-resolution texture pack
pub const RUNTIME_VERSION_1_9_4: u32 = make_exe_version(1, 9, 4);

/// `0x010A0140` beta/release - creation club
pub const RUNTIME_VERSION_1_10_20: u32 = make_exe_version(1, 10, 20);

/// `0x010A01A0` creation club update 2
pub const RUNTIME_VERSION_1_10_26: u32 = make_exe_version(1, 10, 26);

/// `0x010A0280` creation club update 3 (thanks for cleaning up plugin identification)
pub const RUNTIME_VERSION_1_10_40: u32 = make_exe_version(1, 10, 40);

/// `0x010A0320` creation club update 4
pub const RUNTIME_VERSION_1_10_50: u32 = make_exe_version(1, 10, 50);

/// `0x010A0400` creation club update 5
pub const RUNTIME_VERSION_1_10_64: u32 = make_exe_version(1, 10, 64);

/// `0x010A04B0` creation club update 6
pub const RUNTIME_VERSION_1_10_75: u32 = make_exe_version(1, 10, 75);

/// `0x010A0520` creation club update 7 (startup speed?)
pub const RUNTIME_VERSION_1_10_82: u32 = make_exe_version(1, 10, 82);

/// `0x010A0590` creation club update 8
pub const RUNTIME_VERSION_1_10_89: u32 = make_exe_version(1, 10, 89);

/// `0x010A0620` creation club update 9
pub const RUNTIME_VERSION_1_10_98: u32 = make_exe_version(1, 10, 98);

/// `0x010A06A0` creation club update 10 (no addresses changed)
pub const RUNTIME_VERSION_1_10_106: u32 = make_exe_version(1, 10, 106);

/// `0x010A06F0` creation club update 11 (no addresses changed)
pub const RUNTIME_VERSION_1_10_111: u32 = make_exe_version(1, 10, 111);

/// `0x010A0720` creation club update 12 (no addresses changed)
pub const RUNTIME_VERSION_1_10_114: u32 = make_exe_version(1, 10, 114);

/// `0x010A0780` creation club update 13 (no addresses changed)
pub const RUNTIME_VERSION_1_10_120: u32 = make_exe_version(1, 10, 120);

/// `0x010A0820` creation club update 14
pub const RUNTIME_VERSION_1_10_130: u32 = make_exe_version(1, 10, 130);

/// `0x010A08A0` creation club update 15
pub const RUNTIME_VERSION_1_10_138: u32 = make_exe_version(1, 10, 138);

/// `0x010A0A20` creation club update 16
pub const RUNTIME_VERSION_1_10_162: u32 = make_exe_version(1, 10, 162);

/// `0x010A0A30` creation club update 17
pub const RUNTIME_VERSION_1_10_163: u32 = make_exe_version(1, 10, 163);

/// `0x010A3D40` 'next generation' update
pub const RUNTIME_VERSION_1_10_980: u32 = make_exe_version(1, 10, 980);

/// `0x010A3D80` hotfix
pub const RUNTIME_VERSION_1_10_984: u32 = make_exe_version(1, 10, 984);
