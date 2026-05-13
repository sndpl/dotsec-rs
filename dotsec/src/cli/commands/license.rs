use clap::Command;
use std::time::Duration;

use crate::default_options::DefaultOptions;

const LICENSE_TEXT: &str = "\
MIT License

Copyright (c) 2025 JP Wesselink

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.";

pub fn command() -> Command {
    Command::new("license")
        .about("Show the dotsec license")
}

// TODO: replace with chromakopia native plasma once pr-7 ships, e.g.:
//   Plasma::on(LICENSE_TEXT).palette(presets::storm().palette(256)).spawn();
fn plasma_effect(text: &str, frame: usize) -> String {
    use colored::Colorize;
    let t = frame as f64 * 0.06;
    let lines: Vec<&str> = text.split('\n').collect();

    lines
        .iter()
        .enumerate()
        .map(|(row, line)| {
            line.chars()
                .enumerate()
                .map(|(col, ch)| {
                    let x = col as f64 * 0.18;
                    let y = row as f64 * 0.45;

                    // Interference of multiple sine waves — classic plasma
                    let v = (x + t).sin()
                        + (y * 0.7 + t * 0.8).sin()
                        + ((x * 0.5 + y * 0.5 + t * 1.1) * 0.9).sin()
                        + ((x * x + y * y).sqrt() * 0.6 + t * 0.7).sin();

                    // Map [-4, 4] → [0, 1]
                    let norm = (v / 8.0 + 0.5).clamp(0.0, 1.0);

                    // Hue cycling through full spectrum
                    let hue = (norm * 360.0 + t * 25.0) % 360.0;
                    let (r, g, b) = hsv_to_rgb(hue, 1.0, 1.0);

                    ch.to_string().truecolor(r, g, b).to_string()
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// HSV → RGB (all values 0–1 except hue which is 0–360)
fn hsv_to_rgb(h: f64, s: f64, v: f64) -> (u8, u8, u8) {
    let c = v * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = v - c;

    let (r1, g1, b1) = match h as u32 {
        0..=59   => (c, x, 0.0),
        60..=119 => (x, c, 0.0),
        120..=179 => (0.0, c, x),
        180..=239 => (0.0, x, c),
        240..=299 => (x, 0.0, c),
        _         => (c, 0.0, x),
    };

    (
        ((r1 + m) * 255.0) as u8,
        ((g1 + m) * 255.0) as u8,
        ((b1 + m) * 255.0) as u8,
    )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    _default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches.subcommand_matches("license").is_none() {
        return Ok(());
    }

    use chromakopia::animate::{Sequence, TimeRange};

    Sequence::new(LICENSE_TEXT)
        .effect(
            TimeRange::from_duration(Duration::ZERO, Duration::from_secs(4)),
            30,
            plasma_effect,
        )
        .fade_to_foreground(Duration::from_millis(600))
        .run(1.0)
        .await;

    println!();

    Ok(())
}
