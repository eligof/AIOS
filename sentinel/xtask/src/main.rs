use std::path::{Path, PathBuf};
use std::process::Command;

const USAGE: &str = "usage: xtask vmtest <scenario|all>";

/// Run the harness for one scenario; true when it exited 0.
fn run_scenario(sentinel: &Path, scenario: &str) -> bool {
    // Resolve the harness absolutely so the caller's cwd does not matter.
    let harness = sentinel.join("tests/vm/harness.sh");
    Command::new("bash")
        .arg(harness)
        .arg(scenario)
        .current_dir(sentinel)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Every `tests/vm/scenarios/*.sh` (extension stripped). The cheap smoke
/// scenarios run first so a broken object fails fast; the rest are alphabetical.
fn list_scenarios(sentinel: &Path) -> Vec<String> {
    let dir = sentinel.join("tests/vm/scenarios");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let p = e.path();
            (p.extension().and_then(|x| x.to_str()) == Some("sh"))
                .then(|| p.file_stem().unwrap().to_string_lossy().into_owned())
        })
        .collect();
    names.sort();
    // Stable sort: false (first-priority) sorts before true.
    names.sort_by_key(|n| !matches!(n.as_str(), "selftest" | "maps"));
    names
}

/// Run all scenarios, stopping at the first failure; print a summary of what ran.
fn run_all(sentinel: &Path) -> bool {
    let names = list_scenarios(sentinel);
    let mut results: Vec<(String, bool)> = Vec::new();
    for name in &names {
        eprintln!("=== vmtest {name} ({}/{})", results.len() + 1, names.len());
        let ok = run_scenario(sentinel, name);
        results.push((name.clone(), ok));
        if !ok {
            break;
        }
    }
    eprintln!("\n=== vmtest summary");
    for (name, ok) in &results {
        eprintln!("{} {name}", if *ok { "PASS" } else { "FAIL" });
    }
    for name in names.iter().skip(results.len()) {
        eprintln!("SKIP {name}");
    }
    let passed = results.iter().filter(|(_, ok)| *ok).count();
    eprintln!("{passed}/{} scenarios passed", names.len());
    passed == names.len()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("vmtest") => {
            let scenario = args.get(2).unwrap_or_else(|| {
                eprintln!("{USAGE}");
                std::process::exit(2);
            });
            // xtask lives at <sentinel>/xtask.
            let sentinel = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("sentinel dir")
                .to_path_buf();
            let ok = if scenario == "all" {
                run_all(&sentinel)
            } else {
                run_scenario(&sentinel, scenario)
            };
            std::process::exit(if ok { 0 } else { 1 });
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}
