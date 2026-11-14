//! The `sentineld` binary: configuration, threads and the §12 exit paths.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use clap::Parser;

use sentineld::alert::Store;
use sentineld::daemon::Daemon;
use sentineld::engine::{Policy, RuleSet};
use sentineld::kernel::Kernel;
use sentineld::loader::{Mode, RealKernel};
use sentineld::proc::{ProcSource, RealProc};
use sentineld::report::SystemSink;
use sentineld::resolve::HomeBinds;
use sentineld::status::{self, Health};

/// How often the heartbeat is refreshed (spec §8.3 asks for every second; the
/// reference loader uses 500 ms, which leaves margin under a 2 s minimum).
const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

#[derive(Parser)]
#[command(about = "AIOS Sentinel daemon")]
struct Cli {
    /// The rendered `[sentinel]` section.
    #[arg(long, default_value = "/etc/aios/sentinel/sentinel.toml")]
    config: PathBuf,
    /// The rendered rule directory.
    #[arg(long, default_value = "/etc/aios/sentinel/rules.d")]
    rules: PathBuf,
    /// Where alerts are stored.
    #[arg(long, default_value = "/var/log/aios/sentinel")]
    alerts: PathBuf,
    /// The varlink socket.
    #[arg(long, default_value = sentineld::varlink::SOCKET_PATH)]
    socket: PathBuf,
    /// Where the daemon writes `ok` or `degraded`.
    #[arg(long, default_value = status::STATE_PATH)]
    state: PathBuf,
    /// The manifest-managed home targets, one per line (S4 fills this in).
    #[arg(long)]
    home_binds: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // 1. Configuration. An absent file means the documented defaults (§11.1).
    let config = match std::fs::read_to_string(&cli.config) {
        Ok(raw) => sentinel_rules::config::parse(&raw)
            .map_err(|e| anyhow::anyhow!("{}: {e}", cli.config.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            sentinel_rules::config::SentinelConfig::default()
        }
        Err(e) => bail!("{}: {e}", cli.config.display()),
    };
    let problems = sentinel_rules::config::validate(&config);
    if !problems.is_empty() {
        bail!("{}: {}", cli.config.display(), problems.join("; "));
    }
    if !config.enable {
        // Nothing is loaded, so nothing is enforced and there is no lockdown.
        eprintln!("sentineld: disabled by configuration; exiting");
        return Ok(());
    }

    // 2. Rules. Invalid rules at boot are the same path as a load failure (§12).
    let loaded = sentinel_rules::load_dir(&cli.rules).map_err(|errs| {
        anyhow::anyhow!(
            "invalid rules: {}",
            errs.iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        )
    })?;
    let rules = RuleSet::compile(loaded).map_err(|errs| {
        anyhow::anyhow!(
            "rules do not compile: {}",
            errs.iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        )
    })?;

    let lockdown_after_ns = sentinel_rules::validate::parse_duration_ms(&config.lockdown_after)
        .map(|ms| ms * 1_000_000)
        .map_err(|e| anyhow::anyhow!("lockdown_after: {e}"))?;

    // 3. Load the kernel object. A failure here exits, pinning nothing (§12).
    let guarded = vec![
        cli.alerts.clone(),
        PathBuf::from(sentineld::loader::PIN_ROOT),
    ];
    let mut real = RealKernel::load(lockdown_after_ns, true, true, &rules.tables, &guarded)
        .map_err(|e| anyhow::anyhow!("cannot start the kernel side: {e}"))?;
    let degraded = real.mode == Mode::Degraded;
    let attached = real.attached.clone();
    let ring = real.take_ring();

    // 4. Report whatever the kernel did while nobody was watching (§8.3).
    //    Read it before the first heartbeat of this instance.
    let gap = sentineld::lockdown::report(&mut real, lockdown_after_ns);

    let kernel: Arc<Mutex<Box<dyn Kernel>>> = Arc::new(Mutex::new(Box::new(real)));

    // 5. Build the daemon.
    let binds = match &cli.home_binds {
        Some(p) => HomeBinds::new(
            std::fs::read_to_string(p)
                .with_context(|| p.display().to_string())?
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect(),
        ),
        None => HomeBinds::default(),
    };
    let procs = RealProc;
    let journald_pid = procs
        .pids()
        .into_iter()
        .find(|p| {
            procs
                .read(*p)
                .is_some_and(|q| q.exe.ends_with("systemd-journald"))
        })
        .unwrap_or(0);
    let policy = Policy::new(
        std::process::id(),
        journald_pid,
        config.never_act_on.clone(),
    );
    let store = Store::open(&cli.alerts).map_err(|e| anyhow::anyhow!("alert store: {e}"))?;

    let mut daemon = Daemon::new(
        rules,
        config.clone(),
        Box::new(RealProc),
        Box::new(SystemSink::new()),
        store,
        policy,
        binds,
    );
    daemon.seed_table();

    if let Some(g) = gap {
        let now = kernel.lock().map(|k| k.wall_ms()).unwrap_or(0);
        let mut a = daemon.blank_alert("lockdown-gap", "critical", "alerted");
        a.ts = sentineld::daemon::format_ts_pub(now);
        a.message = g.message();
        a.event = g.event();
        daemon.raise(a);
    }
    if degraded {
        let now = kernel.lock().map(|k| k.wall_ms()).unwrap_or(0);
        let mut a = daemon.blank_alert("degraded", "critical", "alerted");
        a.ts = sentineld::daemon::format_ts_pub(now);
        a.message =
            "LSM programs did not attach: observe only, no deny, no self-guard, no lockdown"
                .to_string();
        daemon.raise(a);
    }

    // 6. The Status snapshot the varlink thread serves. Its live fields are
    //    kept current by the heartbeat thread from here on.
    let health = if degraded {
        Health::Degraded
    } else {
        Health::Ok
    };
    let (kernel_rules, user_rules) = daemon.rules.counts();
    daemon.status = Some(sentineld::status::Status {
        version: env!("CARGO_PKG_VERSION").to_string(),
        health,
        programs: attached,
        heartbeat_age_ms: 0,
        lockdown_active: false,
        lockdown_counts: vec![0; sentineld::kernel::NHOOKS],
        kernel_rules,
        user_rules,
        audit_rules: 0,
        generation: daemon.generation.clone(),
        drops: 0,
        quarantines: 0,
        dns_monitor: false,
        store_error: None,
    });

    let daemon = Arc::new(Mutex::new(daemon));
    let stop = Arc::new(AtomicBool::new(false));
    let dns_connected = Arc::new(AtomicBool::new(false));

    // 7. Threads.
    let hb = {
        let kernel = kernel.clone();
        let daemon = daemon.clone();
        let stop = stop.clone();
        let dns_connected = dns_connected.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(mut k) = kernel.lock() {
                    let now = k.monotonic_ns();
                    let _ = k.heartbeat(now);
                    // This thread already holds the kernel, so it is also
                    // where the Status snapshot is kept current (§10.1).
                    if let Ok(mut d) = daemon.lock() {
                        d.refresh_status(
                            k.as_ref(),
                            dns_connected.load(Ordering::Relaxed),
                            lockdown_after_ns,
                        );
                    }
                }
                std::thread::sleep(HEARTBEAT_INTERVAL);
            }
        })
    };

    let drain = {
        let daemon = daemon.clone();
        let kernel = kernel.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let Some(mut ring) = ring else { return };
            sentineld::drain(&mut ring, daemon, kernel, stop);
        })
    };

    let listener = sentineld::varlink::bind(&cli.socket)
        .with_context(|| format!("cannot bind {}", cli.socket.display()))?;
    let svc = Arc::new(sentineld::varlink::Service {
        daemon: daemon.clone(),
        watchers: Arc::new(Mutex::new(Vec::new())),
        kernel: kernel.clone(),
        rules_dir: cli.rules.clone(),
    });

    let dns = {
        let daemon = daemon.clone();
        let kernel = kernel.clone();
        let connected = dns_connected.clone();
        let stop = stop.clone();
        std::thread::spawn(move || sentineld::dns::run(daemon, kernel, connected, stop))
    };

    // 8. Ready.
    status::write_state(&cli.state, health)
        .with_context(|| format!("cannot write {}", cli.state.display()))?;
    status::notify_ready();
    eprintln!("sentineld: ready ({})", health.as_str());

    // 9. Serve until a signal arrives. `RefuseManualStop` means this is only
    //    reached on shutdown or `systemctl kill` (spec §8.2 known limit).
    for conn in listener.incoming() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match conn {
            Ok(c) => {
                let svc = svc.clone();
                std::thread::spawn(move || sentineld::varlink::serve_conn(c, svc));
            }
            Err(e) => eprintln!("sentineld: accept failed: {e}"),
        }
    }

    stop.store(true, Ordering::Relaxed);
    let _ = hb.join();
    let _ = drain.join();
    let _ = dns.join();
    Ok(())
}
