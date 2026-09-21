//! Desktop save-path benchmark.
//!
//! The counterpart to `scripts/benchmark.mjs`, for the core the desktop
//! actually runs. Prints one JSON object per tier, and with `--assert` gates
//! the budgets from `docs/PRODUCT.md`.
//!
//! ```text
//! cargo run --release --features benchmark --bin vbrain-bench -- --notes 1000 --assert
//! ```

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use vault_brain_desktop_lib::benchmark::{edit, inspect, measure, phases, Report};

/// `docs/PRODUCT.md`, "Success measures". The same numbers the TypeScript
/// benchmark gates, so neither core can pass a budget the other fails --
/// including which statistic is gated. The save budget is checked against the
/// median and against the worst sample, not against p95: on a shared CI disk a
/// small fraction of fsyncs stall for hundreds of milliseconds, so p95 reports
/// that run's stall rate rather than the save path. `scripts/benchmark.mjs`
/// carries the measurements behind that decision. p95 is still reported.
const SAVE_BUDGET_MS: f64 = 20.0;
const SAVE_MAX_BUDGET_MS: f64 = 1000.0;
const UNLOCK_BUDGET_MS: f64 = 2000.0;

fn argument(name: &str, fallback: &str) -> String {
    let arguments: Vec<String> = env::args().collect();
    arguments
        .iter()
        .position(|value| value == name)
        .and_then(|index| arguments.get(index + 1))
        .cloned()
        .unwrap_or_else(|| fallback.to_string())
}

fn flag(name: &str) -> bool {
    env::args().any(|value| value == name)
}

fn print(report: &Report) {
    println!(
        "{{\n  \"core\": \"rust\",\n  \"notes\": {},\n  \"bulkCreateMs\": {:.2},\n  \
         \"unlockAndIndexMs\": {:.2},\n  \"indexBytes\": {},\n  \
         \"incrementalSaveMs\": {{ \"p50\": {:.3}, \"p95\": {:.3}, \"max\": {:.3} }}\n}}",
        report.notes,
        report.bulk_create_ms,
        report.unlock_and_index_ms,
        report.index_bytes,
        report.save.p50,
        report.save.p95,
        report.save.max,
    );
}

fn main() -> ExitCode {
    // Cross-core modes, used by test/cross-core-index-log.test.mjs to prove
    // this core reads a change log the TypeScript core wrote, and vice versa.
    if flag("--inspect") {
        let vault = argument("--inspect", "");
        let passphrase = argument("--passphrase", "");
        return match inspect(&vault, &passphrase) {
            Ok(report) => {
                println!("{report}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("inspect failed: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if flag("--phases") {
        let vault = argument("--phases", "");
        let passphrase = argument("--passphrase", "");
        let saves: usize = argument("--saves", "50").parse().unwrap_or(50);
        return match phases(&vault, &passphrase, saves) {
            Ok(report) => {
                println!("{report}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("phases failed: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if flag("--edit") {
        let vault = argument("--edit", "");
        let passphrase = argument("--passphrase", "");
        let note_path = argument("--path", "");
        let body = argument("--body", "");
        return match edit(&vault, &passphrase, &note_path, &body) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("edit failed: {error}");
                ExitCode::FAILURE
            }
        };
    }

    let notes: usize = argument("--notes", "1000").parse().unwrap_or(1000);
    let saves: usize = argument("--saves", "50").parse().unwrap_or(50);
    if !(100..=100_000).contains(&notes) {
        eprintln!("--notes must be between 100 and 100000");
        return ExitCode::FAILURE;
    }

    let root = env::temp_dir().join(format!("vault-brain-rust-bench-{}", std::process::id()));
    if let Err(error) = fs::create_dir_all(&root) {
        eprintln!("could not create the benchmark directory: {error}");
        return ExitCode::FAILURE;
    }

    let outcome = measure(&root, notes, saves);
    remove(&root);

    let report = match outcome {
        Ok(report) => report,
        Err(error) => {
            eprintln!("benchmark failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    print(&report);

    // Always reported, whether or not it is gated: a budget nobody can see is
    // how the desktop came to carry this defect unmeasured.
    let save_met = report.save.p50 < SAVE_BUDGET_MS && report.save.max < SAVE_MAX_BUDGET_MS;
    if !save_met {
        println!(
            "BUDGET MISS: incremental save p50 {:.1}ms / max {:.1}ms against {SAVE_BUDGET_MS:.0}ms and {SAVE_MAX_BUDGET_MS:.0}ms at {} notes (rust core).",
            report.save.p50, report.save.max, report.notes
        );
    }
    if report.save.p95 >= SAVE_BUDGET_MS {
        println!(
            "TAIL: incremental save p95 {:.1}ms is over the {SAVE_BUDGET_MS:.0}ms product budget at {} notes (rust core), with p50 {:.1}ms and max {:.1}ms. Reported, not gated.",
            report.save.p95, report.notes, report.save.p50, report.save.max
        );
    }

    if !flag("--assert") {
        return ExitCode::SUCCESS;
    }

    let mut failed = false;
    if report.unlock_and_index_ms >= UNLOCK_BUDGET_MS {
        eprintln!(
            "unlock {:.1}ms exceeded {UNLOCK_BUDGET_MS:.0}ms at {} notes",
            report.unlock_and_index_ms, report.notes
        );
        failed = true;
    }
    if flag("--enforce-open-budgets") && !save_met {
        eprintln!(
            "incremental save p50 {:.1}ms / max {:.1}ms exceeded {SAVE_BUDGET_MS:.0}ms and {SAVE_MAX_BUDGET_MS:.0}ms at {} notes",
            report.save.p50, report.save.max, report.notes
        );
        failed = true;
    }
    if failed {
        return ExitCode::FAILURE;
    }
    println!(
        "Rust core gates at the {} note tier: PASS{}",
        report.notes,
        if save_met {
            ""
        } else {
            " (incremental save budget is missed; see above)"
        }
    );
    ExitCode::SUCCESS
}

fn remove(path: &PathBuf) {
    if let Err(error) = fs::remove_dir_all(path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            eprintln!("could not clean up {}: {error}", path.display());
        }
    }
}
