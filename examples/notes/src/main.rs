//! `tangra-notes`: the notes module (deployer `cmd/deployersvc`).
//!
//! ```text
//! tangra-notes -config <path>                 serve until SIGINT/SIGTERM
//! tangra-notes bootstrap -config <path>       apply the schema and exit
//! tangra-notes --healthcheck -config <path>   exit 0 when /readyz answers 200
//! tangra-notes version                        print the release
//! ```

use std::process::ExitCode;

use tangra_notes::{VERSION, config, healthcheck, module};
use tangra_sdk::gateway;

const DEFAULT_CONFIG: &str = "/app/config.yaml";

/// Go `flag` style: `-config path`, `--config path`, `-config=path`.
fn config_path(args: &[String]) -> Result<String, String> {
    let mut it = args.iter();
    let mut path = DEFAULT_CONFIG.to_owned();
    while let Some(a) = it.next() {
        let flag = a.trim_start_matches('-');
        if !a.starts_with('-') {
            return Err(format!("unexpected argument {a:?}"));
        }
        match flag.split_once('=') {
            Some(("config", v)) => path = v.to_owned(),
            None if flag == "config" => {
                path = it.next().ok_or("flag needs an argument: -config")?.clone();
            }
            None if flag == "healthcheck" => {}
            _ => return Err(format!("flag provided but not defined: {a}")),
        }
    }
    Ok(path)
}

fn load(args: &[String]) -> Result<config::NotesFile, String> {
    let cfg = config::load(&config_path(args)?).map_err(|e| e.0)?;
    Ok(cfg)
}

async fn serve(args: &[String]) -> Result<(), String> {
    let cfg = load(args)?;
    let notes = module::build(cfg, module::Options::default())
        .await
        .map_err(|e| e.0)?;
    notes.run().await.map_err(|e| e.0)
}

/// Applies the schema. The example stores notes in memory, so there is
/// nothing to migrate; a PostgreSQL module runs its embedded migrations here
/// with `db.migrate_dsn` (`sqlx::migrate!().run(&pool)`) and exits.
fn bootstrap(args: &[String]) -> Result<(), String> {
    load(args)?;
    eprintln!("tangra-notes: in-memory store: nothing to migrate");
    Ok(())
}

async fn health(args: &[String]) -> Result<(), String> {
    let cfg = tangra_sdk::config::Config::<config::NotesConfig>::load(config_path(args)?).map_err(|e| e.0)?;
    healthcheck::probe(&cfg.framework.admin.addr).await
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Report the release to the gateway at registration (Go:
    // gatewayclient.SetBuildVersion(version)).
    gateway::set_build_version(VERSION);
    let first = args.first().map(String::as_str);
    let res = match first {
        Some("version" | "-version" | "--version") => {
            println!("{VERSION}");
            Ok(())
        }
        Some("bootstrap") => bootstrap(&args[1..]),
        _ if args.iter().any(|a| a == "--healthcheck" || a == "-healthcheck") => health(&args).await,
        _ => serve(&args).await,
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tangra-notes: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::config_path;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn flags() {
        assert_eq!(config_path(&args(&[])).unwrap(), "/app/config.yaml");
        assert_eq!(config_path(&args(&["-config", "a.yaml"])).unwrap(), "a.yaml");
        assert_eq!(config_path(&args(&["--config=b.yaml"])).unwrap(), "b.yaml");
        assert_eq!(
            config_path(&args(&["--healthcheck", "-config", "c"])).unwrap(),
            "c"
        );
        assert!(config_path(&args(&["-config"])).is_err());
        assert!(config_path(&args(&["-nope"])).is_err());
    }
}
