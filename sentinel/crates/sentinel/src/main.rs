//! The `sentinel` CLI: status, alerts, watch, quarantine, rules, verify
//! (spec §10.2).

mod client;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use client::{alert_line, since_to_ts, Client, SOCKET_PATH};

#[derive(Parser)]
#[command(about = "AIOS Sentinel control and inspection")]
struct Cli {
    /// The daemon's varlink socket.
    #[arg(long, default_value = SOCKET_PATH, global = true)]
    socket: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Programs, heartbeat, lockdown, rules, quarantines.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Recent alerts.
    Alerts {
        #[arg(long)]
        since: Option<String>,
        #[arg(long = "min")]
        min_severity: Option<String>,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        json: bool,
    },
    /// One alert in full.
    Show { id: String },
    /// Stream alerts as they are raised.
    Watch,
    /// Quarantines.
    #[command(subcommand)]
    Quarantine(QuarantineCmd),
    /// Rules.
    #[command(subcommand)]
    Rules(RulesCmd),
    /// Check the whole alert chain.
    Verify,
}

#[derive(Subcommand)]
enum QuarantineCmd {
    List,
    /// Thaw a quarantine and restore its processes (root).
    Release {
        id: String,
    },
    /// Kill a quarantined process tree (root).
    Kill {
        id: String,
    },
}

#[derive(Subcommand)]
enum RulesCmd {
    /// The rules the daemon has loaded.
    List,
    /// Validate a rule directory offline, like `aios plan` does.
    Check { dir: std::path::PathBuf },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // `rules check` is offline: it never touches the daemon (spec §10.2).
    if let Cmd::Rules(RulesCmd::Check { dir }) = &cli.cmd {
        return rules_check(dir);
    }

    let mut c = Client::connect(&cli.socket)?;
    match cli.cmd {
        Cmd::Status { json } => {
            let p = c.call("Status", serde_json::json!({}))?;
            let s = p.get("status").cloned().unwrap_or_default();
            if json {
                println!("{}", serde_json::to_string_pretty(&s)?);
            } else {
                print_status(&s);
            }
        }
        Cmd::Alerts {
            since,
            min_severity,
            limit,
            json,
        } => {
            let mut params = serde_json::Map::new();
            if let Some(s) = since {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                match since_to_ts(&s, now) {
                    Some(ts) => {
                        params.insert("since".to_string(), ts.into());
                    }
                    None => bail!("--since {s:?} is not a duration (1h, 30m, 2d) or a timestamp"),
                }
            }
            if let Some(m) = min_severity {
                params.insert("minSeverity".to_string(), m.into());
            }
            if let Some(l) = limit {
                params.insert("limit".to_string(), l.into());
            }
            let p = c.call("ListAlerts", serde_json::Value::Object(params))?;
            let alerts = p
                .get("alerts")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default();
            if json {
                println!("{}", serde_json::to_string_pretty(&alerts)?);
            } else if alerts.is_empty() {
                println!("no alerts");
            } else {
                for a in &alerts {
                    println!("{}", alert_line(a));
                }
            }
        }
        Cmd::Show { id } => {
            let p = c.call("GetAlert", serde_json::json!({ "id": id }))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&p.get("alert").cloned().unwrap_or_default())?
            );
        }
        Cmd::Watch => {
            c.call_more("WatchAlerts", serde_json::json!({}), |p| {
                if let Some(a) = p.get("alert") {
                    println!("{}", alert_line(a));
                }
            })?;
        }
        Cmd::Quarantine(QuarantineCmd::List) => {
            let p = c.call("ListQuarantine", serde_json::json!({}))?;
            let qs = p
                .get("quarantines")
                .and_then(|q| q.as_array())
                .cloned()
                .unwrap_or_default();
            if qs.is_empty() {
                println!("no quarantines");
            }
            for q in qs {
                println!(
                    "{:<26}  root pid {:<7}  {} pid(s){}",
                    q.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                    q.get("rootPid").and_then(|v| v.as_u64()).unwrap_or(0),
                    q.get("pids")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0),
                    if q.get("killed").and_then(|v| v.as_bool()) == Some(true) {
                        "  (killed)"
                    } else {
                        ""
                    }
                );
            }
        }
        Cmd::Quarantine(QuarantineCmd::Release { id }) => {
            c.call("Release", serde_json::json!({ "id": id }))?;
            println!("released {id}");
        }
        Cmd::Quarantine(QuarantineCmd::Kill { id }) => {
            c.call("Kill", serde_json::json!({ "id": id }))?;
            println!("killed {id}");
        }
        Cmd::Rules(RulesCmd::List) => {
            let p = c.call("Status", serde_json::json!({}))?;
            let s = p.get("status").cloned().unwrap_or_default();
            println!(
                "{} kernel rule(s), {} user-space rule(s), generation {}",
                s.get("kernelRules").and_then(|v| v.as_u64()).unwrap_or(0),
                s.get("userRules").and_then(|v| v.as_u64()).unwrap_or(0),
                s.get("generation").and_then(|v| v.as_str()).unwrap_or("-")
            );
        }
        Cmd::Rules(RulesCmd::Check { .. }) => unreachable!("handled above"),
        Cmd::Verify => {
            let p = c.call("VerifyChain", serde_json::json!({}))?;
            if p.get("ok").and_then(|o| o.as_bool()) == Some(true) {
                println!(
                    "alert chain is intact ({} record(s))",
                    p.get("records").and_then(|r| r.as_u64()).unwrap_or(0)
                );
            } else {
                bail!(
                    "alert chain is broken: {}",
                    p.get("error").and_then(|e| e.as_str()).unwrap_or("unknown")
                );
            }
        }
    }
    Ok(())
}

/// One `Status` field as plain text. `Value`'s own `Display` is JSON, so it
/// would print `health "ok"` with the quotes, and a list as `["exec","bpf"]`.
fn field(s: &serde_json::Value, key: &str) -> String {
    match s.get(key) {
        None | Some(serde_json::Value::Null) => "-".to_string(),
        Some(serde_json::Value::String(v)) => v.clone(),
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect::<Vec<_>>()
            .join(", "),
        Some(other) => other.to_string(),
    }
}

fn print_status(s: &serde_json::Value) {
    let g = |k: &str| field(s, k);
    println!("version        {}", g("version"));
    println!("health         {}", g("health"));
    println!("programs       {}", g("programs"));
    println!("heartbeat age  {} ms", g("heartbeatAgeMs"));
    println!("lockdown       {}", g("lockdownActive"));
    println!(
        "rules          {} kernel, {} user",
        g("kernelRules"),
        g("userRules")
    );
    println!("generation     {}", g("generation"));
    println!("ring drops     {}", g("drops"));
    println!("quarantines    {}", g("quarantines"));
    println!("dns monitor    {}", g("dnsMonitor"));
    if let Some(e) = s.get("storeError").and_then(|e| e.as_str()) {
        println!("store error    {e}");
    }
}

/// Offline validation, the same `sentinel-rules` path `aios plan` uses.
fn rules_check(dir: &std::path::Path) -> Result<()> {
    match sentinel_rules::load_dir(dir) {
        Ok(rules) => match sentinel_rules::matcher::compile_all(&rules) {
            Ok((tables, user)) => {
                println!(
                    "{} rule(s) valid: {} kernel, {} user-space",
                    rules.len(),
                    tables.rules.len(),
                    user.len()
                );
                Ok(())
            }
            Err(errs) => {
                for e in &errs {
                    eprintln!("{e}");
                }
                bail!("{} rule(s) do not compile", errs.len())
            }
        },
        Err(errs) => {
            for e in &errs {
                eprintln!("{e}");
            }
            bail!("{} problem(s) in {}", errs.len(), dir.display())
        }
    }
}
