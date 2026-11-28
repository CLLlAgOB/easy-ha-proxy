//! CLI utility for differential parity testing (`parse`) and benchmarking (`bench`)
//! of the Rust `guardd-core` hot path.

use guardd_core::{parse_access_line, IpMemory, SignatureEngine, SubnetCorrelator};
use std::env;
use std::io::{self, BufRead, BufWriter, Write};
use std::process::ExitCode;
use std::time::Instant;

mod serve;

fn load_signatures(path: Option<&str>) -> SignatureEngine {
    match path {
        Some(p) if !p.is_empty() => SignatureEngine::from_file(p).unwrap_or_else(|e| {
            eprintln!("warning: {e}; using built-in signatures");
            SignatureEngine::builtin()
        }),
        _ => SignatureEngine::builtin(),
    }
}

fn cmd_parse(sig_path: Option<&str>) -> ExitCode {
    let sigs = load_signatures(sig_path);
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for line_res in stdin.lock().lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                eprintln!("stdin read error: {e}");
                return ExitCode::FAILURE;
            }
        };
        let parsed = parse_access_line(&line, &sigs);
        let (path_cat, ua_token, ua_cat) = match &parsed {
            Some(req) => {
                let pc = sigs.classify_path(&req.path);
                let (ut, uc) = sigs.classify_user_agent(&req.user_agent);
                (pc, ut, uc)
            }
            None => ("", "", ""),
        };
        let record = serde_json::json!({
            "parsed": parsed,
            "path_category": path_cat,
            "ua_token": ua_token,
            "ua_category": ua_cat,
        });
        if let Err(e) = writeln!(out, "{record}") {
            eprintln!("stdout write error: {e}");
            return ExitCode::FAILURE;
        }
    }
    let _ = out.flush();
    ExitCode::SUCCESS
}

fn cmd_bench(lines_count: usize, sig_path: Option<&str>) -> ExitCode {
    let sigs = load_signatures(sig_path);
    let sample_normal = "2026-08-11T06:18:05.912571+00:00 haproxy-easy haproxy[976]: \
        203.0.113.42:2160 [11/Aug/2026:06:18:05.863] fe_https~ be_app/ui \
        11/0/0/30/47 200 786 ----- 1/1/0/0/0 0/0 \
        host=app.example.com ua=Mozilla/5.0_(Windows_NT_10.0;_Win64;_x64) \
        GET https://app.example.com/api/v1/items?page=1&limit=20 HTTP/2.0";
    let sample_attack = "2026-08-11T07:26:51.104063+00:00 haproxy-easy haproxy[976]: \
        198.51.100.77:60374 [11/Aug/2026:07:26:51.096] fe_https~ fe_https/<NOSRV> \
        0/-1/-1/-1/6 404 58 PR--- 1/1/0/0/0 0/0 \
        host=app.example.com ua=sqlmap/1.7 \
        GET /.env?id=1%27%20UNION%20SELECT%201,2-- HTTP/1.1";

    // 1. Pure parse_access_line benchmark (normal)
    let t0 = Instant::now();
    let mut parsed_ok = 0usize;
    for _ in 0..lines_count {
        if let Some(r) = parse_access_line(sample_normal, &sigs) {
            parsed_ok += r.status as usize;
        }
    }
    let dt_normal = t0.elapsed().as_secs_f64();

    // 2. Pure parse_access_line benchmark (attack)
    let t1 = Instant::now();
    for _ in 0..lines_count {
        if let Some(r) = parse_access_line(sample_attack, &sigs) {
            parsed_ok += r.status as usize;
        }
    }
    let dt_attack = t1.elapsed().as_secs_f64();

    // 3. Full hot-path pipeline: parse + classify_path + classify_user_agent + IpMemory SLRU + SubnetCorrelator
    let mut batch: Vec<String> = Vec::with_capacity(lines_count);
    for i in 0..lines_count {
        let uri = if (i & 3) == 0 {
            "/.env?id=1%27+UNION+SELECT+1--"
        } else {
            "/api/items?page=1"
        };
        let st = if (i & 3) == 0 { 404 } else { 200 };
        batch.push(format!(
            "2026-08-11T07:26:51.104063+00:00 haproxy-easy haproxy[976]: \
             198.51.100.{}:60374 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1 \
             0/0/0/1/1 {} 210 ----- 1/1/0/0/0 0/0 \
             host=app.example.com ua=Mozilla/5.0 \
             GET {} HTTP/1.1",
            (i % 250) + 1,
            st,
            uri
        ));
    }

    let mut mem = IpMemory::new(5000, 32);
    let mut corr = SubnetCorrelator::default_config();
    let t2 = Instant::now();
    let mut hits = 0usize;
    for (idx, line) in batch.iter().enumerate() {
        if let Some(req) = parse_access_line(line, &sigs) {
            let now = 1_786_429_000 + (idx as i64 / 100);
            let act = mem.touch(&req.client_ip, now);
            act.requests += 1;
            act.note_path(&req.path, now, 32);
            let cat = sigs.classify_path(&req.path);
            let (_ut, ucat) = sigs.classify_user_agent(&req.user_agent);
            if !cat.is_empty() || !ucat.is_empty() {
                act.scanner_hits += 1;
                if !cat.is_empty() {
                    act.note_category(cat, now, 16);
                }
                mem.promote(&req.client_ip);
                let (_sub, count) = corr.observe(&req.client_ip, now);
                if count >= 3 {
                    hits += 1;
                }
            }
        }
    }
    let dt_pipeline = t2.elapsed().as_secs_f64();

    println!("guardd-core Rust benchmark (signatures: {})", sigs.version);
    println!(
        "  parse_access_line (normal): {:>10.0} lines/sec ({:>5.2} us/line)",
        (lines_count as f64) / dt_normal,
        dt_normal * 1e6 / (lines_count as f64)
    );
    println!(
        "  parse_access_line (attack): {:>10.0} lines/sec ({:>5.2} us/line)",
        (lines_count as f64) / dt_attack,
        dt_attack * 1e6 / (lines_count as f64)
    );
    println!(
        "  full hot-path (parse + classify + SLRU IpMemory + /24 SubnetCorrelator): {:>10.0} req/sec ({:>5.2} us/req, {} subnet hits, check={})",
        (lines_count as f64) / dt_pipeline,
        dt_pipeline * 1e6 / (lines_count as f64),
        hits,
        parsed_ok
    );
    ExitCode::SUCCESS
}

/// Write a known event and request through the Rust stores, for the parity
/// test that reads them back with the Python daemon's own code.
fn cmd_seed_db(sec_path: &str, req_path: &str, sig_path: Option<&str>) -> ExitCode {
    use guardd_core::reqlog::RequestLog;
    use guardd_core::secdb::{NewEvent, SecurityDatabase};
    use guardd_core::{score_events, GuardConfig, ScoringPolicy, Verdict};
    let sigs = load_signatures(sig_path);
    let sec = match SecurityDatabase::open(sec_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("security.db open error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let verdict = Verdict {
        excluded: false,
        reason: String::new(),
        source: String::new(),
    };
    let seeded = sec
        .set_state("mode_override", "enforce")
        .and_then(|_| sec.observe_ip("198.51.100.77", 1_786_429_000, &verdict))
        .and_then(|_| {
            sec.record_events(&[NewEvent {
                ts: 1_786_429_000,
                ip: "198.51.100.77".into(),
                event_type: "SCANNER_PATH_DECISIVE".into(),
                source: "log".into(),
                site: "app.example.com".into(),
                category: "secrets".into(),
                detail: "/.env".into(),
                handled: false,
            }])
        });
    if let Err(e) = seeded {
        eprintln!("security.db write error: {e}");
        return ExitCode::FAILURE;
    }
    let evs = sec.events_for("198.51.100.77", 0, 500).unwrap_or_default();
    let score = score_events(&evs, 1_786_429_000, &ScoringPolicy::default());
    let cfg = GuardConfig {
        request_log_enabled: true,
        ..Default::default()
    };
    let rlog = match RequestLog::open(req_path, &cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("requests.db open error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let sample = "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]:         198.51.100.77:60374 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1         0/0/0/2/3 404 210 ----- 1/1/0/0/0 0/0 host=app.example.com ua=sqlmap/1.7         GET /.env HTTP/1.1";
    if let Some(req) = parse_access_line(sample, &sigs) {
        rlog.add(&req, Some(1_786_429_000.0));
        rlog.flush(1_786_429_000);
    }
    println!(
        "{}",
        serde_json::json!({
            "score": score.score,
            "state": score.state,
            "recommended_action": score.recommended_action,
            "events_counted": score.events_counted,
        })
    );
    ExitCode::SUCCESS
}

const USAGE: &str = "usage: guardd-core <serve|parse|bench|seed-db> [--config PATH] [--database PATH] [--socket PATH] [--signatures PATH] [--lines N]";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let sub = args.get(1).map(String::as_str).unwrap_or("bench");
    let mut opts: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
    let mut i = 2;
    while i < args.len() {
        let key = match args[i].as_str() {
            "--signatures" => Some("signatures"),
            "--security-db" | "--database" => Some("database"),
            "--requests-db" => Some("requests"),
            "--config" => Some("config"),
            "--socket" => Some("socket"),
            "--lines" => Some("lines"),
            _ => None,
        };
        if let (Some(k), Some(v)) = (key, args.get(i + 1)) {
            opts.insert(k, v.clone());
            i += 2;
            continue;
        }
        i += 1;
    }
    let opt = |k: &str, env_name: &str, default: &str| {
        opts.get(k)
            .cloned()
            .unwrap_or_else(|| env::var(env_name).unwrap_or_else(|_| default.to_string()))
    };
    match sub {
        "parse" => cmd_parse(opts.get("signatures").map(String::as_str)),
        "bench" => {
            let lines = opts
                .get("lines")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(50_000)
                .max(1);
            cmd_bench(lines, opts.get("signatures").map(String::as_str))
        }
        "serve" => serve::run(serve::Paths {
            config: opt("config", "GUARDD_CONFIG", "/opt/haproxy-admin/guardd.json"),
            database: opt(
                "database",
                "GUARDD_DATABASE",
                "/var/lib/easy-ha-proxy/security/security.db",
            ),
            socket: opt(
                "socket",
                "GUARDD_SOCKET_PATH",
                "/run/easy-ha-proxy/easy-ha-proxy-guardd.sock",
            ),
            signatures: opt(
                "signatures",
                "GUARDD_SIGNATURES",
                "/usr/local/sbin/scanner-signatures.json",
            ),
            request_log: opt(
                "requests",
                "GUARDD_REQUEST_LOG",
                "/var/lib/easy-ha-proxy/requests/requests.db",
            ),
        }),
        "seed-db" => match (opts.get("database"), opts.get("requests")) {
            (Some(sec), Some(req)) => {
                cmd_seed_db(sec, req, opts.get("signatures").map(String::as_str))
            }
            _ => {
                eprintln!("usage: guardd-core seed-db --security-db PATH --requests-db PATH [--signatures PATH]");
                ExitCode::from(2)
            }
        },
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        "-V" | "--version" | "version" => {
            println!("guardd-core {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
