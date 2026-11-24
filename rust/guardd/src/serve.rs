//! `guardd-core serve`: the daemon (Python `guardd.api.main`).

use guardd_core::alerts::AlertClient;
use guardd_core::api::{
    apply_overrides, load_overrides, load_shipped_signatures, request_log_wanted,
};
use guardd_core::constants::{utc_now_f, MODE_OFF};
use guardd_core::engine::{self, Engine, Shared};
use guardd_core::reqlog::RequestLog;
use guardd_core::runtime::load_config;
use guardd_core::secdb::SecurityDatabase;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

pub struct Paths {
    pub config: String,
    pub database: String,
    pub socket: String,
    pub signatures: String,
    pub request_log: String,
}

static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn on_signal(_sig: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_signal_handlers() {
    // SAFETY: the handler only stores into an atomic.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
}

#[cfg(not(unix))]
fn install_signal_handlers() {}

pub fn run(paths: Paths) -> ExitCode {
    install_signal_handlers();
    std::env::set_var("GUARDD_SIGNATURES", &paths.signatures);
    let shipped = load_shipped_signatures(&paths.signatures);
    let config = load_config(&paths.config);
    let db = match SecurityDatabase::open(&paths.database) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            eprintln!(
                "[ERROR] easy-ha-proxy-guardd: cannot open security database {}: {e}",
                paths.database
            );
            return ExitCode::FAILURE;
        }
    };
    let overrides = load_overrides(&db);
    let merged = Arc::new(apply_overrides(&shipped, &overrides));
    let want_requests = request_log_wanted(&db, &config);
    if config.mode == MODE_OFF && !want_requests {
        eprintln!(
            "[INFO] easy-ha-proxy-guardd: Adaptive protection is off in {}; idling",
            paths.config
        );
        while !STOP.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(500));
        }
        return ExitCode::SUCCESS;
    }
    let requests = if want_requests {
        match RequestLog::open(&paths.request_log, &config) {
            Ok(r) => Some(Arc::new(r)),
            Err(e) => {
                eprintln!("[WARNING] easy-ha-proxy-guardd: request log unavailable: {e}");
                None
            }
        }
    } else {
        None
    };
    let requests = Arc::new(RwLock::new(requests));
    let sigs = Arc::new(RwLock::new(merged));
    let engine = Engine::new(
        config.clone(),
        db.clone(),
        sigs.clone(),
        AlertClient::from_env(),
        requests.clone(),
    );
    eprintln!(
        "[INFO] easy-ha-proxy-guardd: Starting easy-ha-proxy-guardd (Rust): mode={} (configured {}) socket={} db={} log={} interval={}s exclusions={} networks",
        engine.enforcer.mode,
        config.mode,
        paths.socket,
        paths.database,
        config.log_file,
        config.poll_interval_seconds,
        engine.sink.exclusions.network_count()
    );
    let stop = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(Shared {
        live: engine.live.clone(),
        lag_bytes: engine.lag_bytes.clone(),
        engine: Mutex::new(engine),
        stop: stop.clone(),
        db: db.clone(),
        requests,
        sigs,
        shipped: Mutex::new(Arc::new(shipped)),
        overrides: Mutex::new(overrides),
        config,
        token: std::env::var("GUARDD_TOKEN")
            .unwrap_or_default()
            .trim()
            .to_string(),
        request_log_path: paths.request_log.clone(),
    });
    // Mirror the process-wide signal into the shared stop flag.
    let signal_watcher = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                if STOP.load(Ordering::SeqCst) {
                    stop.store(true, Ordering::SeqCst);
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        })
    };
    let collector = {
        let s = shared.clone();
        std::thread::spawn(move || engine::run(s))
    };
    #[cfg(unix)]
    let served = guardd_core::api::serve(&paths.socket, shared.clone());
    #[cfg(not(unix))]
    let served: Result<(), String> = Err("serve requires Unix sockets".into());
    stop.store(true, Ordering::SeqCst);
    let _ = signal_watcher.join();
    let collected = collector.join();
    shared.engine().stop();
    if let Some(store) = shared
        .requests
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
    {
        store.flush(utc_now_f() as i64);
    }
    eprintln!("[INFO] easy-ha-proxy-guardd: Received signal; shutting down");
    match served {
        Ok(()) if collected.is_ok() => ExitCode::SUCCESS,
        Ok(()) => {
            eprintln!("[ERROR] easy-ha-proxy-guardd: collector panicked");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("[ERROR] easy-ha-proxy-guardd: {e}");
            ExitCode::FAILURE
        }
    }
}
