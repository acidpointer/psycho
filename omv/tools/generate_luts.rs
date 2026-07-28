//! Regenerate OMV's original redistributable 32^3 .cube look library.

use std::{env, fs, path::Path};

#[derive(Clone, Copy)]
struct Recipe {
    contrast: f32,
    saturation: f32,
    gamma: f32,
    black_fade: f32,
    balance: [f32; 3],
    shadow_tint: [f32; 3],
    highlight_tint: [f32; 3],
}

#[derive(Clone, Copy)]
struct CinematicRecipe {
    contrast: f32,
    gamma: f32,
    black_lift: f32,
    highlight_rolloff: f32,
    saturation: [f32; 3],
    balance: [f32; 3],
    shadow_tint: [f32; 3],
    midtone_tint: [f32; 3],
    highlight_tint: [f32; 3],
    hue_selective: [f32; 3],
}

const LOOKS: &[(&str, &str, Option<Recipe>)] = &[
    ("00_neutral.cube", "Neutral", None),
    (
        "01_mojave_natural.cube",
        "Mojave Natural",
        Some(Recipe {
            contrast: 0.045,
            saturation: 1.015,
            gamma: 0.99,
            black_fade: 0.004,
            balance: [0.008, 0.002, -0.007],
            shadow_tint: [-0.005, 0.001, 0.008],
            highlight_tint: [0.010, 0.003, -0.008],
        }),
    ),
    (
        "02_dusty_western.cube",
        "Dusty Western",
        Some(Recipe {
            contrast: 0.09,
            saturation: 0.88,
            gamma: 0.975,
            black_fade: 0.010,
            balance: [0.024, 0.010, -0.021],
            shadow_tint: [0.006, 0.003, -0.006],
            highlight_tint: [0.020, 0.008, -0.017],
        }),
    ),
    (
        "03_bleached_wasteland.cube",
        "Bleached Wasteland",
        Some(Recipe {
            contrast: 0.12,
            saturation: 0.70,
            gamma: 1.015,
            black_fade: 0.025,
            balance: [0.006, 0.006, 0.002],
            shadow_tint: [-0.002, 0.005, 0.010],
            highlight_tint: [0.012, 0.010, 0.002],
        }),
    ),
    (
        "04_neon_nights.cube",
        "Neon Nights",
        Some(Recipe {
            contrast: 0.08,
            saturation: 1.14,
            gamma: 1.005,
            black_fade: 0.012,
            balance: [-0.005, -0.003, 0.014],
            shadow_tint: [-0.017, 0.003, 0.030],
            highlight_tint: [0.023, -0.003, 0.017],
        }),
    ),
    (
        "05_high_desert_clarity.cube",
        "High Desert Clarity",
        Some(Recipe {
            contrast: 0.065,
            saturation: 1.08,
            gamma: 0.985,
            black_fade: 0.004,
            balance: [0.004, 0.002, -0.003],
            shadow_tint: [-0.004, 0.002, 0.009],
            highlight_tint: [0.006, 0.004, -0.004],
        }),
    ),
    (
        "06_atomic_amber.cube",
        "Atomic Amber",
        Some(Recipe {
            contrast: 0.10,
            saturation: 0.95,
            gamma: 0.975,
            black_fade: 0.010,
            balance: [0.025, 0.010, -0.022],
            shadow_tint: [0.008, 0.003, -0.012],
            highlight_tint: [0.025, 0.012, -0.026],
        }),
    ),
    (
        "07_frontier_cinema.cube",
        "Frontier Cinema",
        Some(Recipe {
            contrast: 0.13,
            saturation: 0.90,
            gamma: 0.99,
            black_fade: 0.014,
            balance: [0.008, 0.001, -0.006],
            shadow_tint: [-0.018, 0.008, 0.022],
            highlight_tint: [0.026, 0.009, -0.018],
        }),
    ),
    (
        "08_old_world_film.cube",
        "Old World Film",
        Some(Recipe {
            contrast: 0.06,
            saturation: 0.78,
            gamma: 1.02,
            black_fade: 0.035,
            balance: [0.014, 0.008, -0.006],
            shadow_tint: [0.009, 0.008, 0.005],
            highlight_tint: [0.018, 0.012, -0.008],
        }),
    ),
    (
        "09_vault_fluorescent.cube",
        "Vault Fluorescent",
        Some(Recipe {
            contrast: 0.09,
            saturation: 0.86,
            gamma: 1.01,
            black_fade: 0.012,
            balance: [-0.012, 0.012, 0.010],
            shadow_tint: [-0.020, 0.018, 0.025],
            highlight_tint: [-0.005, 0.010, 0.008],
        }),
    ),
    (
        "10_sierra_sunset.cube",
        "Sierra Sunset",
        Some(Recipe {
            contrast: 0.09,
            saturation: 1.06,
            gamma: 0.98,
            black_fade: 0.010,
            balance: [0.018, -0.003, 0.006],
            shadow_tint: [-0.008, -0.004, 0.018],
            highlight_tint: [0.030, 0.001, 0.008],
        }),
    ),
    (
        "11_zion_canyon.cube",
        "Zion Canyon",
        Some(Recipe {
            contrast: 0.075,
            saturation: 1.12,
            gamma: 0.99,
            black_fade: 0.006,
            balance: [0.016, 0.006, -0.008],
            shadow_tint: [-0.003, 0.010, 0.006],
            highlight_tint: [0.025, 0.010, -0.015],
        }),
    ),
    (
        "12_divide_duststorm.cube",
        "Divide Duststorm",
        Some(Recipe {
            contrast: 0.15,
            saturation: 0.68,
            gamma: 0.97,
            black_fade: 0.018,
            balance: [0.028, 0.014, -0.022],
            shadow_tint: [0.012, 0.006, -0.009],
            highlight_tint: [0.034, 0.018, -0.025],
        }),
    ),
    (
        "13_wasteland_noir.cube",
        "Wasteland Noir",
        Some(Recipe {
            contrast: 0.18,
            saturation: 0.32,
            gamma: 1.01,
            black_fade: 0.012,
            balance: [0.004, 0.004, 0.004],
            shadow_tint: [-0.003, 0.002, 0.008],
            highlight_tint: [0.008, 0.006, 0.001],
        }),
    ),
];

const CINEMATIC_LOOKS: &[(&str, &str, CinematicRecipe)] = &[
    (
        "14_midnight_mojave.cube",
        "Midnight Mojave",
        CinematicRecipe {
            contrast: 0.14,
            gamma: 1.025,
            black_lift: 0.012,
            highlight_rolloff: 0.045,
            saturation: [0.70, 0.86, 0.80],
            balance: [-0.003, 0.000, 0.006],
            shadow_tint: [-0.016, 0.002, 0.026],
            midtone_tint: [-0.006, 0.001, 0.010],
            highlight_tint: [0.018, 0.006, -0.014],
            hue_selective: [0.14, -0.04, 0.10],
        },
    ),
    (
        "15_desert_noir.cube",
        "Desert Noir",
        CinematicRecipe {
            contrast: 0.19,
            gamma: 1.005,
            black_lift: 0.010,
            highlight_rolloff: 0.040,
            saturation: [0.32, 0.52, 0.62],
            balance: [0.002, 0.001, 0.000],
            shadow_tint: [-0.010, 0.002, 0.015],
            midtone_tint: [0.004, 0.001, -0.003],
            highlight_tint: [0.022, 0.009, -0.016],
            hue_selective: [0.22, -0.10, 0.02],
        },
    ),
    (
        "16_vegas_after_dark.cube",
        "Vegas After Dark",
        CinematicRecipe {
            contrast: 0.13,
            gamma: 1.015,
            black_lift: 0.014,
            highlight_rolloff: 0.055,
            saturation: [0.76, 1.04, 0.94],
            balance: [0.001, -0.002, 0.006],
            shadow_tint: [-0.018, 0.010, 0.022],
            midtone_tint: [0.010, -0.008, 0.015],
            highlight_tint: [0.026, 0.008, -0.012],
            hue_selective: [0.18, -0.04, 0.16],
        },
    ),
    (
        "17_rain_on_freeside.cube",
        "Rain on Freeside",
        CinematicRecipe {
            contrast: 0.10,
            gamma: 1.025,
            black_lift: 0.020,
            highlight_rolloff: 0.065,
            saturation: [0.52, 0.70, 0.66],
            balance: [-0.006, 0.004, 0.009],
            shadow_tint: [-0.015, 0.008, 0.022],
            midtone_tint: [-0.008, 0.008, 0.010],
            highlight_tint: [0.020, 0.010, -0.015],
            hue_selective: [0.15, -0.08, 0.08],
        },
    ),
    (
        "18_sierra_madre_gilded.cube",
        "Sierra Madre Gilded",
        CinematicRecipe {
            contrast: 0.14,
            gamma: 0.995,
            black_lift: 0.026,
            highlight_rolloff: 0.060,
            saturation: [0.56, 0.76, 0.68],
            balance: [0.009, 0.005, -0.006],
            shadow_tint: [-0.006, 0.009, 0.010],
            midtone_tint: [0.014, 0.008, -0.012],
            highlight_tint: [0.030, 0.016, -0.022],
            hue_selective: [0.18, -0.06, -0.04],
        },
    ),
    (
        "19_dead_money_poison.cube",
        "Dead Money Poison",
        CinematicRecipe {
            contrast: 0.17,
            gamma: 1.020,
            black_lift: 0.014,
            highlight_rolloff: 0.055,
            saturation: [0.46, 0.66, 0.70],
            balance: [-0.004, 0.008, -0.001],
            shadow_tint: [-0.012, 0.018, 0.004],
            midtone_tint: [-0.006, 0.014, -0.004],
            highlight_tint: [0.018, 0.014, -0.016],
            hue_selective: [0.24, 0.04, -0.08],
        },
    ),
    (
        "20_mojave_blue_hour.cube",
        "Mojave Blue Hour",
        CinematicRecipe {
            contrast: 0.09,
            gamma: 0.975,
            black_lift: 0.014,
            highlight_rolloff: 0.070,
            saturation: [0.76, 0.90, 0.92],
            balance: [-0.004, -0.001, 0.009],
            shadow_tint: [-0.018, -0.002, 0.028],
            midtone_tint: [-0.006, 0.000, 0.014],
            highlight_tint: [0.028, 0.010, -0.008],
            hue_selective: [0.16, -0.04, 0.14],
        },
    ),
    (
        "21_caravan_lantern.cube",
        "Caravan Lantern",
        CinematicRecipe {
            contrast: 0.12,
            gamma: 0.985,
            black_lift: 0.012,
            highlight_rolloff: 0.050,
            saturation: [0.60, 0.84, 0.88],
            balance: [0.006, 0.002, -0.005],
            shadow_tint: [-0.012, 0.002, 0.016],
            midtone_tint: [0.012, 0.005, -0.010],
            highlight_tint: [0.032, 0.014, -0.024],
            hue_selective: [0.20, -0.06, -0.02],
        },
    ),
    (
        "22_dust_and_blood.cube",
        "Dust and Blood",
        CinematicRecipe {
            contrast: 0.16,
            gamma: 1.000,
            black_lift: 0.013,
            highlight_rolloff: 0.055,
            saturation: [0.40, 0.60, 0.68],
            balance: [0.006, 0.002, -0.004],
            shadow_tint: [-0.010, 0.001, 0.014],
            midtone_tint: [0.010, 0.004, -0.008],
            highlight_tint: [0.026, 0.010, -0.018],
            hue_selective: [0.34, -0.16, -0.10],
        },
    ),
    (
        "23_atomic_monochrome.cube",
        "Atomic Monochrome",
        CinematicRecipe {
            contrast: 0.20,
            gamma: 1.005,
            black_lift: 0.018,
            highlight_rolloff: 0.045,
            saturation: [0.08, 0.15, 0.22],
            balance: [0.001, 0.002, 0.003],
            shadow_tint: [-0.008, 0.001, 0.012],
            midtone_tint: [0.002, 0.002, 0.001],
            highlight_tint: [0.014, 0.010, -0.004],
            hue_selective: [0.12, -0.04, 0.02],
        },
    ),
    (
        "24_vault_noir.cube",
        "Vault Noir",
        CinematicRecipe {
            contrast: 0.13,
            gamma: 1.015,
            black_lift: 0.016,
            highlight_rolloff: 0.050,
            saturation: [0.46, 0.66, 0.74],
            balance: [-0.008, 0.009, 0.008],
            shadow_tint: [-0.016, 0.014, 0.020],
            midtone_tint: [-0.010, 0.012, 0.010],
            highlight_tint: [0.016, 0.009, -0.008],
            hue_selective: [0.24, -0.04, 0.02],
        },
    ),
    (
        "25_lonesome_road_ash.cube",
        "Lonesome Road Ash",
        CinematicRecipe {
            contrast: 0.18,
            gamma: 1.020,
            black_lift: 0.010,
            highlight_rolloff: 0.075,
            saturation: [0.28, 0.46, 0.56],
            balance: [0.002, 0.002, 0.003],
            shadow_tint: [-0.010, 0.001, 0.014],
            midtone_tint: [0.002, 0.002, 0.001],
            highlight_tint: [0.022, 0.010, -0.016],
            hue_selective: [0.24, -0.12, -0.06],
        },
    ),
    (
        "26_radioactive_dream.cube",
        "Radioactive Dream",
        CinematicRecipe {
            contrast: 0.10,
            gamma: 0.990,
            black_lift: 0.022,
            highlight_rolloff: 0.065,
            saturation: [0.70, 0.96, 0.92],
            balance: [-0.004, 0.005, 0.006],
            shadow_tint: [-0.018, 0.016, 0.018],
            midtone_tint: [0.006, -0.006, 0.014],
            highlight_tint: [0.022, -0.002, 0.012],
            hue_selective: [0.20, 0.02, 0.14],
        },
    ),
    (
        "27_old_world_detective.cube",
        "Old World Detective",
        CinematicRecipe {
            contrast: 0.15,
            gamma: 1.000,
            black_lift: 0.030,
            highlight_rolloff: 0.070,
            saturation: [0.26, 0.40, 0.46],
            balance: [0.007, 0.006, 0.002],
            shadow_tint: [-0.004, 0.006, 0.008],
            midtone_tint: [0.010, 0.008, -0.004],
            highlight_tint: [0.024, 0.016, -0.010],
            hue_selective: [0.16, -0.08, -0.04],
        },
    ),
    (
        "28_capital_wasteland_overcast.cube",
        "Capital Wasteland Overcast",
        CinematicRecipe {
            contrast: 0.10,
            gamma: 1.010,
            black_lift: 0.016,
            highlight_rolloff: 0.070,
            saturation: [0.48, 0.65, 0.60],
            balance: [-0.003, 0.004, 0.002],
            shadow_tint: [-0.008, 0.012, 0.010],
            midtone_tint: [-0.003, 0.006, 0.004],
            highlight_tint: [0.014, 0.010, -0.012],
            hue_selective: [0.22, -0.04, -0.08],
        },
    ),
    (
        "29_potomac_fog.cube",
        "Potomac Fog",
        CinematicRecipe {
            contrast: 0.04,
            gamma: 1.035,
            black_lift: 0.035,
            highlight_rolloff: 0.090,
            saturation: [0.38, 0.55, 0.52],
            balance: [-0.002, 0.005, 0.006],
            shadow_tint: [-0.008, 0.008, 0.012],
            midtone_tint: [-0.004, 0.006, 0.008],
            highlight_tint: [0.010, 0.012, 0.004],
            hue_selective: [0.16, -0.05, 0.02],
        },
    ),
    (
        "30_ruined_capitol_dusk.cube",
        "Ruined Capitol Dusk",
        CinematicRecipe {
            contrast: 0.13,
            gamma: 0.990,
            black_lift: 0.018,
            highlight_rolloff: 0.070,
            saturation: [0.60, 0.80, 0.82],
            balance: [0.004, -0.002, 0.006],
            shadow_tint: [-0.014, -0.003, 0.022],
            midtone_tint: [0.004, -0.004, 0.010],
            highlight_tint: [0.030, 0.008, -0.010],
            hue_selective: [0.22, -0.10, 0.12],
        },
    ),
    (
        "31_dc_radstorm.cube",
        "DC Radstorm",
        CinematicRecipe {
            contrast: 0.16,
            gamma: 1.010,
            black_lift: 0.012,
            highlight_rolloff: 0.060,
            saturation: [0.52, 0.78, 0.70],
            balance: [0.002, 0.008, -0.008],
            shadow_tint: [-0.006, 0.014, 0.000],
            midtone_tint: [0.004, 0.012, -0.010],
            highlight_tint: [0.020, 0.014, -0.020],
            hue_selective: [0.24, 0.08, -0.16],
        },
    ),
    (
        "32_underworld_embers.cube",
        "Underworld Embers",
        CinematicRecipe {
            contrast: 0.18,
            gamma: 1.015,
            black_lift: 0.024,
            highlight_rolloff: 0.055,
            saturation: [0.34, 0.62, 0.76],
            balance: [0.004, 0.001, -0.001],
            shadow_tint: [-0.012, 0.004, 0.012],
            midtone_tint: [0.012, 0.004, -0.010],
            highlight_tint: [0.036, 0.014, -0.028],
            hue_selective: [0.28, -0.12, -0.08],
        },
    ),
    (
        "33_subterranean_survival.cube",
        "Subterranean Survival",
        CinematicRecipe {
            contrast: 0.17,
            gamma: 1.020,
            black_lift: 0.018,
            highlight_rolloff: 0.080,
            saturation: [0.45, 0.70, 0.74],
            balance: [-0.004, 0.002, 0.006],
            shadow_tint: [-0.018, 0.008, 0.020],
            midtone_tint: [-0.006, 0.002, 0.008],
            highlight_tint: [0.030, 0.012, -0.022],
            hue_selective: [0.28, -0.08, 0.02],
        },
    ),
    (
        "34_emergency_red.cube",
        "Emergency Red",
        CinematicRecipe {
            contrast: 0.20,
            gamma: 1.010,
            black_lift: 0.014,
            highlight_rolloff: 0.060,
            saturation: [0.42, 0.76, 0.82],
            balance: [0.004, -0.004, 0.002],
            shadow_tint: [-0.014, 0.006, 0.016],
            midtone_tint: [0.014, -0.010, -0.004],
            highlight_tint: [0.038, -0.010, -0.012],
            hue_selective: [0.42, -0.18, -0.10],
        },
    ),
    (
        "35_frozen_platform.cube",
        "Frozen Platform",
        CinematicRecipe {
            contrast: 0.12,
            gamma: 1.030,
            black_lift: 0.026,
            highlight_rolloff: 0.090,
            saturation: [0.50, 0.68, 0.66],
            balance: [-0.010, 0.004, 0.014],
            shadow_tint: [-0.016, 0.006, 0.026],
            midtone_tint: [-0.010, 0.004, 0.016],
            highlight_tint: [0.006, 0.012, 0.010],
            hue_selective: [0.18, -0.06, 0.14],
        },
    ),
    (
        "36_dry_sea_white_sun.cube",
        "Dry Sea White Sun",
        CinematicRecipe {
            contrast: 0.11,
            gamma: 0.965,
            black_lift: 0.012,
            highlight_rolloff: 0.120,
            saturation: [0.40, 0.58, 0.54],
            balance: [0.010, 0.006, -0.006],
            shadow_tint: [0.010, 0.004, -0.008],
            midtone_tint: [0.016, 0.008, -0.014],
            highlight_tint: [0.026, 0.018, -0.010],
            hue_selective: [0.18, -0.10, 0.04],
        },
    ),
    (
        "37_dead_city_blue.cube",
        "Dead City Blue",
        CinematicRecipe {
            contrast: 0.19,
            gamma: 1.025,
            black_lift: 0.020,
            highlight_rolloff: 0.080,
            saturation: [0.18, 0.32, 0.40],
            balance: [-0.006, 0.004, 0.010],
            shadow_tint: [-0.014, 0.006, 0.018],
            midtone_tint: [-0.008, 0.004, 0.012],
            highlight_tint: [0.008, 0.010, 0.006],
            hue_selective: [0.12, -0.06, 0.06],
        },
    ),
    (
        "38_exclusion_overcast.cube",
        "Exclusion Overcast",
        CinematicRecipe {
            contrast: 0.09,
            gamma: 1.020,
            black_lift: 0.022,
            highlight_rolloff: 0.080,
            saturation: [0.38, 0.60, 0.56],
            balance: [0.000, 0.006, 0.000],
            shadow_tint: [-0.008, 0.010, 0.006],
            midtone_tint: [0.002, 0.008, -0.002],
            highlight_tint: [0.016, 0.012, -0.010],
            hue_selective: [0.22, 0.02, -0.10],
        },
    ),
    (
        "39_emission_warning.cube",
        "Emission Warning",
        CinematicRecipe {
            contrast: 0.18,
            gamma: 1.005,
            black_lift: 0.015,
            highlight_rolloff: 0.065,
            saturation: [0.54, 0.84, 0.82],
            balance: [0.006, -0.006, 0.008],
            shadow_tint: [-0.004, -0.006, 0.018],
            midtone_tint: [0.014, -0.010, 0.010],
            highlight_tint: [0.034, -0.008, 0.006],
            hue_selective: [0.34, -0.16, 0.10],
        },
    ),
    (
        "40_rusted_laboratory.cube",
        "Rusted Laboratory",
        CinematicRecipe {
            contrast: 0.17,
            gamma: 1.015,
            black_lift: 0.019,
            highlight_rolloff: 0.060,
            saturation: [0.44, 0.68, 0.72],
            balance: [-0.004, 0.006, 0.002],
            shadow_tint: [-0.014, 0.012, 0.014],
            midtone_tint: [-0.006, 0.008, 0.004],
            highlight_tint: [0.028, 0.012, -0.020],
            hue_selective: [0.30, 0.00, -0.06],
        },
    ),
    (
        "41_pripyat_memory.cube",
        "Pripyat Memory",
        CinematicRecipe {
            contrast: 0.10,
            gamma: 1.010,
            black_lift: 0.032,
            highlight_rolloff: 0.075,
            saturation: [0.30, 0.48, 0.50],
            balance: [0.006, 0.008, 0.001],
            shadow_tint: [-0.004, 0.008, 0.006],
            midtone_tint: [0.010, 0.010, -0.004],
            highlight_tint: [0.026, 0.018, -0.012],
            hue_selective: [0.18, -0.04, -0.08],
        },
    ),
];

fn main() {
    let output = env::args().nth(1).expect("usage: generate_luts OUTPUT_DIR");
    fs::create_dir_all(&output).expect("create LUT output directory");
    for &(file_name, title, recipe) in LOOKS {
        fs::write(
            Path::new(&output).join(file_name),
            generate_cube(title, recipe),
        )
        .expect("write LUT");
    }
    for &(file_name, title, recipe) in CINEMATIC_LOOKS {
        fs::write(
            Path::new(&output).join(file_name),
            generate_cinematic_cube(title, recipe),
        )
        .expect("write cinematic LUT");
    }
}

fn generate_cube(title: &str, recipe: Option<Recipe>) -> String {
    const SIZE: u32 = 32;
    let mut output = format!(
        "# Original OMV LUT; redistribution permitted with OMV.\nTITLE \"{title}\"\nLUT_3D_SIZE {SIZE}\nDOMAIN_MIN 0.0 0.0 0.0\nDOMAIN_MAX 1.0 1.0 1.0\n"
    );
    let denominator = (SIZE - 1) as f32;
    for blue in 0..SIZE {
        for green in 0..SIZE {
            for red in 0..SIZE {
                let input = [
                    red as f32 / denominator,
                    green as f32 / denominator,
                    blue as f32 / denominator,
                ];
                let color = apply_recipe(input, recipe);
                output.push_str(&format!(
                    "{:.6} {:.6} {:.6}\n",
                    color[0], color[1], color[2]
                ));
            }
        }
    }
    output
}

fn apply_recipe(input: [f32; 3], recipe: Option<Recipe>) -> [f32; 3] {
    let Some(recipe) = recipe else {
        return input;
    };
    let mut color = input.map(|value| {
        (0.5 + (value - 0.5) * (1.0 + recipe.contrast))
            .clamp(0.0, 1.0)
            .powf(recipe.gamma)
    });
    let luma = color[0] * 0.2126 + color[1] * 0.7152 + color[2] * 0.0722;
    for channel in &mut color {
        *channel = luma + (*channel - luma) * recipe.saturation;
    }
    let shadow = 1.0 - smooth_step(0.10, 0.62, luma);
    let highlight = smooth_step(0.42, 0.92, luma);
    for channel in 0..3 {
        color[channel] += recipe.balance[channel]
            + recipe.shadow_tint[channel] * shadow
            + recipe.highlight_tint[channel] * highlight;
        color[channel] = recipe.black_fade + color[channel] * (1.0 - recipe.black_fade);
        color[channel] = color[channel].clamp(0.0, 1.0);
    }
    color
}

fn generate_cinematic_cube(title: &str, recipe: CinematicRecipe) -> String {
    const SIZE: u32 = 32;
    let mut output = format!(
        "# Original OMV LUT; redistribution permitted with OMV.\nTITLE \"{title}\"\nLUT_3D_SIZE {SIZE}\nDOMAIN_MIN 0.0 0.0 0.0\nDOMAIN_MAX 1.0 1.0 1.0\n"
    );
    let denominator = (SIZE - 1) as f32;
    for blue in 0..SIZE {
        for green in 0..SIZE {
            for red in 0..SIZE {
                let input = [
                    red as f32 / denominator,
                    green as f32 / denominator,
                    blue as f32 / denominator,
                ];
                let color = apply_cinematic_recipe(input, recipe);
                output.push_str(&format!(
                    "{:.6} {:.6} {:.6}\n",
                    color[0], color[1], color[2]
                ));
            }
        }
    }
    output
}

fn apply_cinematic_recipe(input: [f32; 3], recipe: CinematicRecipe) -> [f32; 3] {
    let luma = input[0] * 0.2126 + input[1] * 0.7152 + input[2] * 0.0722;
    let curved = luma.powf(recipe.gamma);
    let contrasted = curved + (smooth_step(0.0, 1.0, curved) - curved) * recipe.contrast;
    let rolled = contrasted - recipe.highlight_rolloff * contrasted * contrasted;
    let tone = (recipe.black_lift + rolled * (1.0 - recipe.black_lift)).clamp(0.0, 1.0);

    let shadow = 1.0 - smooth_step(0.08, 0.48, luma);
    let highlight = smooth_step(0.52, 0.94, luma);
    let midtone = (1.0 - shadow).min(1.0 - highlight);
    let saturation = recipe.saturation[0] * shadow
        + recipe.saturation[1] * midtone
        + recipe.saturation[2] * highlight;

    let mut candidate = input.map(|channel| tone + (channel - luma) * saturation);
    for channel in 0..3 {
        let other_average = (input[(channel + 1) % 3] + input[(channel + 2) % 3]) * 0.5;
        let dominance = (input[channel] - other_average).max(0.0);
        candidate[channel] += recipe.hue_selective[channel] * dominance;
        candidate[channel] += recipe.balance[channel]
            + recipe.shadow_tint[channel] * shadow
            + recipe.midtone_tint[channel] * midtone
            + recipe.highlight_tint[channel] * highlight;
    }

    fit_gamut_around_tone(candidate, tone)
}

fn fit_gamut_around_tone(candidate: [f32; 3], tone: f32) -> [f32; 3] {
    let mut scale = 1.0f32;
    for channel in candidate {
        let delta = channel - tone;
        if delta > 0.0 {
            scale = scale.min((1.0 - tone) / delta);
        } else if delta < 0.0 {
            scale = scale.min(tone / -delta);
        }
    }
    candidate.map(|channel| (tone + (channel - tone) * scale.clamp(0.0, 1.0)).clamp(0.0, 1.0))
}

fn smooth_step(low: f32, high: f32, value: f32) -> f32 {
    let value = ((value - low) / (high - low)).clamp(0.0, 1.0);
    value * value * (3.0 - 2.0 * value)
}
