//! CLI utility for differential parity testing (`parse`) and benchmarking (`bench`)
//! of the Rust `guardd-core` hot path.

use guardd_core::{
    load_config, parse_access_line, score_events, DaemonState, Enforcer, EnforcementQueue,
    IpMemory, LiveBuffer, MinuteDigests, RequestLogDb, ScoringPolicy, SecurityDatabase,
    SignatureEngine, SubnetCorrelator,
};
#[cfg(unix)]
use guardd_core::serve_unix_socket;
use std::env;
use std::io::{self, BufRead, BufWriter, Write};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Instant;

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

fn cmd_seed_db(sec_path: &str, req_path: &str, sig_path: Option<&str>) -> ExitCode {
    let sigs = load_signatures(sig_path);
    let sec = match SecurityDatabase::open(sec_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("security.db open error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let _ = sec.set_state("mode_override", "enforce");
    let _ = sec.upsert_ip_state("198.51.100.77", 1_786_429_000, false, "");
    let _ = sec.record_event(
        1_786_429_000,
        "198.51.100.77",
        "SCANNER_PATH_DECISIVE",
        "log",
        "app.example.com",
        "secrets",
        "/.env",
        false,
    );
    let evs = sec.events_for_ip("198.51.100.77", 0).unwrap_or_default();
    let score = score_events(&evs, 1_786_429_000, &ScoringPolicy::default());

    let mut rdb = match RequestLogDb::open(req_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("requests.db open error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let sample = "2026-08-11T07:26:51.104063+00:00 gw haproxy[10]: \
        198.51.100.77:60374 [11/Aug/2026:07:26:51.096] fe_https~ be_app/s1 \
        0/0/0/2/3 404 210 ----- 1/1/0/0/0 0/0 host=app.example.com ua=sqlmap/1.7 \
        GET /.env HTTP/1.1";
    if let Some(req) = parse_access_line(sample, &sigs) {
        if let Err(e) = rdb.insert_batch(&[req]) {
            eprintln!("requests.db insert error: {e}");
            return ExitCode::FAILURE;
        }
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

#[cfg(unix)]
fn cmd_serve(
    config_path: &str,
    db_path: &str,
    socket_path: &str,
    sig_path: Option<&str>,
) -> ExitCode {
    let cfg = load_config(config_path);
    let sigs = load_signatures(sig_path);
    let db = match SecurityDatabase::open(db_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot open security database {db_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mode_override = db.get_state("mode_override", "");
    let enf = Enforcer::new(&cfg, if mode_override.is_empty() { None } else { Some(&mode_override) });
    let token = env::var("GUARDD_TOKEN").unwrap_or_default();
    let state = Arc::new(Mutex::new(DaemonState {
        live: LiveBuffer::new(cfg.live_buffer_records, cfg.live_buffer_seconds, 0),
        memory: IpMemory::new(cfg.max_tracked_ips, cfg.max_paths_per_ip),
        config: cfg,
        signatures: sigs,
        database: db,
        enforcer: enf,
        queue: EnforcementQueue::new(10_000),
        subnets: SubnetCorrelator::default_config(),
        digests: MinuteDigests::new(),
        policy: ScoringPolicy::default(),
        control_token: token,
        lines_read: 0,
        lines_parsed: 0,
    }));
    let stop = Arc::new(AtomicBool::new(false));
    if let Err(e) = serve_unix_socket(socket_path, state, stop) {
        eprintln!("guardd-core serve failed: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(not(unix))]
fn cmd_serve(_config_path: &str, _db_path: &str, _socket_path: &str, _sig_path: Option<&str>) -> ExitCode {
    eprintln!("serve requires Unix AF_UNIX sockets");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let sub = args.get(1).map(String::as_str).unwrap_or("bench");
    let mut sig_path: Option<String> = None;
    let mut sec_db: Option<String> = None;
    let mut req_db: Option<String> = None;
    let mut cfg_path: Option<String> = None;
    let mut sock_path: Option<String> = None;
    let mut lines: usize = 50_000;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--signatures" => {
                if let Some(v) = args.get(i + 1) {
                    sig_path = Some(v.clone());
                    i += 2;
                    continue;
                }
            }
            "--security-db" | "--database" => {
                if let Some(v) = args.get(i + 1) {
                    sec_db = Some(v.clone());
                    i += 2;
                    continue;
                }
            }
            "--requests-db" => {
                if let Some(v) = args.get(i + 1) {
                    req_db = Some(v.clone());
                    i += 2;
                    continue;
                }
            }
            "--config" => {
                if let Some(v) = args.get(i + 1) {
                    cfg_path = Some(v.clone());
                    i += 2;
                    continue;
                }
            }
            "--socket" => {
                if let Some(v) = args.get(i + 1) {
                    sock_path = Some(v.clone());
                    i += 2;
                    continue;
                }
            }
            "--lines" => {
                if let Some(v) = args.get(i + 1) {
                    if let Ok(n) = v.parse::<usize>() {
                        lines = n.max(1);
                    }
                    i += 2;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }

    match sub {
        "parse" => cmd_parse(sig_path.as_deref()),
        "bench" => cmd_bench(lines, sig_path.as_deref()),
        "serve" => {
            let cfg = cfg_path.unwrap_or_else(|| {
                env::var("GUARDD_CONFIG").unwrap_or_else(|_| "/opt/haproxy-admin/guardd.json".to_string())
            });
            let db = sec_db.unwrap_or_else(|| {
                env::var("GUARDD_DATABASE")
                    .unwrap_or_else(|_| "/var/lib/easy-ha-proxy/security/security.db".to_string())
            });
            let sock = sock_path.unwrap_or_else(|| {
                env::var("GUARDD_SOCKET_PATH")
                    .unwrap_or_else(|_| "/run/easy-ha-proxy/easy-ha-proxy-guardd.sock".to_string())
            });
            cmd_serve(&cfg, &db, &sock, sig_path.as_deref())
        }
        "seed-db" => match (sec_db.as_deref(), req_db.as_deref()) {
            (Some(s), Some(r)) => cmd_seed_db(s, r, sig_path.as_deref()),
            _ => {
                eprintln!("usage: guardd-core seed-db --security-db PATH --requests-db PATH [--signatures PATH]");
                ExitCode::from(2)
            }
        },
        "-h" | "--help" | "help" => {
            println!("usage: guardd-core <parse|bench|serve|seed-db> [--signatures PATH] [--lines N]");
            ExitCode::SUCCESS
        }
        "-V" | "--version" | "version" => {
            println!("guardd-core {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: guardd-core <parse|bench|serve|seed-db> [--signatures PATH] [--lines N]");
            ExitCode::from(2)
        }
    }
}
