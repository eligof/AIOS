use std::path::PathBuf;
use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("vmtest") => {
            let scenario = args.get(2).expect("usage: xtask vmtest <scenario>");
            // xtask lives at <sentinel>/xtask; resolve the harness absolutely so
            // the cwd of the caller does not matter.
            let sentinel = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("sentinel dir")
                .to_path_buf();
            let harness = sentinel.join("tests/vm/harness.sh");
            let status = Command::new("bash")
                .arg(harness)
                .arg(scenario)
                .current_dir(&sentinel)
                .status()
                .expect("failed to run harness");
            std::process::exit(status.code().unwrap_or(1));
        }
        _ => {
            eprintln!("usage: xtask vmtest <scenario>");
            std::process::exit(2);
        }
    }
}
