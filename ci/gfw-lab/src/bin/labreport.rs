//! `labreport`: assemble the final lab verdict from the per-component JSON
//! artifacts (scenario outcomes, active-probe report, passive box report) and
//! decide pass/fail. Centralising the policy here keeps it typed and testable.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;

use gfw_lab::report::{ActiveProbeReport, GfwBoxReport, LabReport, ScenarioOutcome};

#[derive(Parser)]
#[command(name = "labreport", about = "Assemble the ParallaX GFW-lab verdict")]
struct Cli {
    /// Transport under test (tcp | quic).
    #[arg(long, default_value = "tcp")]
    transport: String,
    /// Per-scenario ScenarioOutcome JSON files (repeatable).
    #[arg(long = "scenario")]
    scenarios: Vec<PathBuf>,
    /// Active differential-probe report JSON (optional).
    #[arg(long)]
    probe: Option<PathBuf>,
    /// Passive GFW-box analysis report JSON (optional).
    #[arg(long)]
    box_report: Option<PathBuf>,
    /// Output path for the assembled LabReport JSON.
    #[arg(long, default_value = "lab-report.json")]
    out: PathBuf,
}

fn load<T: serde::de::DeserializeOwned>(p: &PathBuf) -> Result<T> {
    let data = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
    serde_json::from_str(&data).with_context(|| format!("parse {}", p.display()))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut scenarios: Vec<ScenarioOutcome> = Vec::new();
    for p in &cli.scenarios {
        scenarios.push(load(p)?);
    }
    let probe: Option<ActiveProbeReport> = match &cli.probe {
        Some(p) => Some(load(p)?),
        None => None,
    };
    let passive: Option<GfwBoxReport> = match &cli.box_report {
        Some(p) => Some(load(p)?),
        None => None,
    };

    // Pass policy:
    //   * every scenario completed (ok == true), AND
    //   * the passive middle-box flagged ZERO flows as a proxy, AND
    //   * the active differential prober found NO distinguisher vs the origin.
    let scenarios_ok = scenarios.iter().all(|s| s.ok);
    let failed_scenarios: Vec<&str> = scenarios
        .iter()
        .filter(|s| !s.ok)
        .map(|s| s.scenario.as_str())
        .collect();
    let passive_ok = passive
        .as_ref()
        .map(|p| p.flagged_flows == 0)
        .unwrap_or(true);
    let probe_ok = probe.as_ref().map(|p| !p.any_distinguisher).unwrap_or(true);

    let pass = scenarios_ok && passive_ok && probe_ok;

    let summary = format!(
        "transport={} scenarios={}/{} passed{}{} | passive: {} flows, {} flagged | active probe: {} | verdict={}",
        cli.transport,
        scenarios.iter().filter(|s| s.ok).count(),
        scenarios.len(),
        if failed_scenarios.is_empty() {
            String::new()
        } else {
            format!(" (failed: {})", failed_scenarios.join(","))
        },
        "",
        passive.as_ref().map(|p| p.total_flows).unwrap_or(0),
        passive.as_ref().map(|p| p.flagged_flows).unwrap_or(0),
        match &probe {
            Some(p) if p.any_distinguisher => "DISTINGUISHABLE",
            Some(_) => "resistant",
            None => "n/a",
        },
        if pass { "PASS" } else { "FAIL" }
    );

    let report = LabReport {
        schema: LabReport::SCHEMA.to_string(),
        generated_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
        transport: cli.transport.clone(),
        scenarios,
        active_probe: probe,
        passive,
        pass,
        summary: summary.clone(),
    };

    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(&cli.out, json).with_context(|| format!("write {}", cli.out.display()))?;

    println!("{summary}");
    if pass {
        Ok(())
    } else {
        std::process::exit(1);
    }
}
