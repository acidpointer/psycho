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

fn smooth_step(low: f32, high: f32, value: f32) -> f32 {
    let value = ((value - low) / (high - low)).clamp(0.0, 1.0);
    value * value * (3.0 - 2.0 * value)
}
