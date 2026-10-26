// best-tunnel-agent: the resident watcher for Tunnel Studio Pro.
//
// What it does, and nothing more:
//   * every `check_interval_secs`, it checks the systemd units named in
//     its config (and ONLY those - see `is_owned`) plus one local TCP
//     connect to the delivery port on its own host;
//   * if an owned unit is not active, it restarts it - but only under
//     the anti-flap policy (at most `max_restarts_per_hour` restarts in
//     any rolling hour, and never sooner than `restart_cooldown_secs`
//     after the previous restart);
//   * if the units are up but delivery fails, it reports and does NOT
//     restart: restarting a healthy unit fixes no backend problem;
//   * it writes a heartbeat JSON file and appends JSONL events, so the
//     dashboard (when the laptop is back) can read what happened while
//     it was away. A missing heartbeat IS the down signal (Phase 5).
//
// What it never does, by construction:
//   * it has no network listener and makes no outbound connection;
//   * it never runs a mutating systemctl verb other than `restart`,
//     and never on a unit outside its config list;
//   * it never switches protocols (decision D2: restart + report only;
//     switching waits for operator trust, and needs a new binary);
//   * it never updates itself: a new binary arrives only through the
//     orchestrator's verified install (checksum-pinned, like every
//     other binary in this product).
//
// Config: a tiny line-based subset of TOML (no external parser, so no
// crates). Keys: role, units (["a", "b"]), delivery_port,
// check_interval_secs, max_restarts_per_hour, restart_cooldown_secs,
// heartbeat_file, events_file. Unknown keys are ignored.

use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
struct Config {
    role: String,
    units: Vec<String>,
    delivery_port: u16,
    check_interval_secs: u64,
    max_restarts_per_hour: usize,
    restart_cooldown_secs: u64,
    heartbeat_file: String,
    events_file: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            role: "unknown".to_string(),
            units: Vec::new(),
            delivery_port: 443,
            check_interval_secs: 15,
            max_restarts_per_hour: 3,
            restart_cooldown_secs: 60,
            heartbeat_file: "/var/lib/best-tunnel/agent-heartbeat.json".to_string(),
            events_file: "/var/log/best-tunnel/agent-events.jsonl".to_string(),
        }
    }
}

fn parse_config(text: &str) -> Config {
    let mut cfg = Config::default();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let eq = match line.find('=') {
            Some(i) => i,
            None => continue,
        };
        let key = line[..eq].trim();
        let val = line[eq + 1..].trim();
        match key {
            "role" => cfg.role = unquote(val),
            "delivery_port" => cfg.delivery_port = val.parse().unwrap_or(443),
            "check_interval_secs" => cfg.check_interval_secs = val.parse().unwrap_or(15),
            "max_restarts_per_hour" => cfg.max_restarts_per_hour = val.parse().unwrap_or(3),
            "restart_cooldown_secs" => cfg.restart_cooldown_secs = val.parse().unwrap_or(60),
            "heartbeat_file" => cfg.heartbeat_file = unquote(val),
            "events_file" => cfg.events_file = unquote(val),
            "units" => {
                // ["a", "b"] - split on commas, strip quotes/whitespace.
                let inner = val.trim_start_matches('[').trim_end_matches(']');
                cfg.units = inner
                    .split(',')
                    .map(|s| unquote(s.trim()))
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            _ => {}
        }
    }
    cfg
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

struct Agent {
    cfg: Config,
    restarts: VecDeque<u64>,
    last_restart: u64,
    last_event: String,
}

impl Agent {
    fn is_owned(&self, unit: &str) -> bool {
        self.cfg.units.iter().any(|u| u == unit)
    }

    fn unit_active(unit: &str) -> bool {
        match Command::new("systemctl").arg("is-active").arg(unit).output() {
            Ok(out) => String::from_utf8_lossy(&out.stdout).trim() == "active",
            Err(_) => false,
        }
    }

    fn delivery_ok(&self) -> bool {
        let addr = ("127.0.0.1", self.cfg.delivery_port);
        match addr.to_socket_addrs() {
            Ok(mut it) => match it.next() {
                Some(sock) => {
                    TcpStream::connect_timeout(&sock, Duration::from_secs(3)).is_ok()
                }
                None => false,
            },
            Err(_) => false,
        }
    }

    // The ONLY mutating action in the whole binary. The owned check is
    // the guard: a unit outside the config list can never reach the
    // systemctl call, whatever the caller asked for.
    fn restart_owned(&mut self, unit: &str) -> Result<(), String> {
        if !self.is_owned(unit) {
            return Err(format!("refused: {} is not an owned unit", unit));
        }
        let now = now_unix();
        while let Some(front) = self.restarts.front() {
            if now.saturating_sub(*front) > 3600 {
                self.restarts.pop_front();
            } else {
                break;
            }
        }
        if self.restarts.len() >= self.cfg.max_restarts_per_hour {
            return Err("refused: flap limit reached".to_string());
        }
        if now.saturating_sub(self.last_restart) < self.cfg.restart_cooldown_secs
            && self.last_restart != 0
        {
            return Err("refused: restart cooldown".to_string());
        }
        let out = Command::new("systemctl")
            .arg("restart")
            .arg(unit)
            .output()
            .map_err(|e| format!("systemctl failed to spawn: {}", e))?;
        if !out.status.success() {
            return Err(format!(
                "systemctl restart failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        self.restarts.push_back(now);
        self.last_restart = now;
        Ok(())
    }

    fn log_event(&mut self, kind: &str, detail: &str) {
        let line = format!(
            "{{\"ts\":{},\"role\":\"{}\",\"event\":\"{}\",\"detail\":\"{}\"}}\n",
            now_unix(),
            json_escape(&self.cfg.role),
            json_escape(kind),
            json_escape(detail)
        );
        self.last_event = format!("{}: {}", kind, detail);
        if let Some(parent) = std::path::Path::new(&self.cfg.events_file).parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.cfg.events_file)
        {
            let _ = f.write_all(line.as_bytes());
        }
        println!("[agent] {}", line.trim());
    }

    fn write_heartbeat(&self, units_state: &[(String, bool)], delivery: bool) {
        let mut units_json = String::new();
        for (i, (u, active)) in units_state.iter().enumerate() {
            if i > 0 {
                units_json.push(',');
            }
            units_json.push_str(&format!("\"{}\":{}", json_escape(u), active));
        }
        let body = format!(
            "{{\"ts\":{},\"role\":\"{}\",\"units\":{{{}}},\"delivery_ok\":{},\"restarts_last_hour\":{},\"last_event\":\"{}\"}}",
            now_unix(),
            json_escape(&self.cfg.role),
            units_json,
            delivery,
            self.restarts.len(),
            json_escape(&self.last_event)
        );
        if let Some(parent) = std::path::Path::new(&self.cfg.heartbeat_file).parent() {
            let _ = fs::create_dir_all(parent);
        }
        // Atomic: temp file + rename, so a reader never sees a torn write.
        let tmp = format!("{}.tmp", self.cfg.heartbeat_file);
        if fs::write(&tmp, body).is_ok() {
            let _ = fs::rename(&tmp, &self.cfg.heartbeat_file);
        }
    }

    fn check_once(&mut self) {
        let mut states: Vec<(String, bool)> = Vec::new();
        for unit in self.cfg.units.clone() {
            let active = Self::unit_active(&unit);
            states.push((unit.clone(), active));
            if !active {
                match self.restart_owned(&unit) {
                    Ok(()) => self.log_event(
                        "unit_restarted",
                        &format!("{} was not active; restarted under policy", unit),
                    ),
                    Err(reason) => self.log_event(
                        "restart_refused",
                        &format!("{} not active; {}", unit, reason),
                    ),
                }
            }
        }
        let delivery = self.delivery_ok();
        if !delivery {
            let all_up = states.iter().all(|(_, a)| *a);
            if all_up {
                // Units healthy, delivery dead: a backend problem, not a
                // unit problem. Report only - restarting would fix nothing
                // and would churn a healthy unit.
                self.log_event(
                    "delivery_failed",
                    "owned units active but local delivery port does not answer",
                );
            }
        }
        self.write_heartbeat(&states, delivery);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = "/etc/best-tunnel/agent.toml".to_string();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" && i + 1 < args.len() {
            config_path = args[i + 1].clone();
            i += 2;
        } else {
            i += 1;
        }
    }
    let text = fs::read_to_string(&config_path).unwrap_or_else(|e| {
        eprintln!("[agent] cannot read config {}: {}", config_path, e);
        std::process::exit(2);
    });
    let cfg = parse_config(&text);
    if cfg.units.is_empty() {
        eprintln!("[agent] config names no units; refusing to run with an empty owned set");
        std::process::exit(2);
    }
    println!(
        "[agent] starting: role={} units={:?} delivery_port={} interval={}s",
        cfg.role, cfg.units, cfg.delivery_port, cfg.check_interval_secs
    );
    let mut agent = Agent {
        cfg,
        restarts: VecDeque::new(),
        last_restart: 0,
        last_event: "started".to_string(),
    };
    loop {
        agent.check_once();
        thread::sleep(Duration::from_secs(agent.cfg.check_interval_secs));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses_the_documented_keys() {
        let cfg = parse_config(
            "role = \"iran\"\nunits = [\"a.service\", \"b.service\"]\n\
             delivery_port = 443\ncheck_interval_secs = 15\n\
             max_restarts_per_hour = 3\nrestart_cooldown_secs = 60\n\
             heartbeat_file = \"/tmp/hb.json\"\nevents_file = \"/tmp/ev.jsonl\"\n",
        );
        assert_eq!(cfg.role, "iran");
        assert_eq!(cfg.units, vec!["a.service", "b.service"]);
        assert_eq!(cfg.delivery_port, 443);
        assert_eq!(cfg.max_restarts_per_hour, 3);
    }

    #[test]
    fn restart_refuses_a_unit_outside_the_owned_set() {
        // The owned path is covered by the live acceptance test, not
        // here: a unit test must never issue a real systemctl restart.
        let mut agent = Agent {
            cfg: Config {
                units: vec!["owned.service".to_string()],
                ..Config::default()
            },
            restarts: VecDeque::new(),
            last_restart: 0,
            last_event: String::new(),
        };
        let err = agent.restart_owned("someone-else.service").unwrap_err();
        assert!(err.contains("not an owned unit"), "{}", err);
    }
}
