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
    /// Passive GFW-box analysis report JSON(s), one per link profile (repeatable).
    #[arg(long = "box-report")]
    box_reports: Vec<PathBuf>,
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
    // Load every per-profile passive report and aggregate. The verdict must
    // account for ALL profiles, not just one.
    let mut passive_reports: Vec<GfwBoxReport> = Vec::new();
    for p in &cli.box_reports {
        passive_reports.push(load(p)?);
    }
    let passive_total_flows: usize = passive_reports.iter().map(|p| p.total_flows).sum();
    let passive_flagged_flows: usize = passive_reports.iter().map(|p| p.flagged_flows).sum();
    // Keep the last profile's report as the representative artifact in the JSON.
    let passive: Option<GfwBoxReport> = passive_reports.last().cloned();

    // Pass policy:
    //   * every scenario completed (ok == true), AND
    //   * the passive middle-box flagged ZERO flows as a proxy (across ALL
    //     profiles), AND
    //   * the active differential prober found NO distinguisher vs the origin.
    let scenarios_ok = scenarios.iter().all(|s| s.ok);
    let failed_scenarios: Vec<&str> = scenarios
        .iter()
        .filter(|s| !s.ok)
        .map(|s| s.scenario.as_str())
        .collect();
    let passive_ok = passive_flagged_flows == 0;
    let probe_ok = probe.as_ref().map(|p| !p.any_distinguisher).unwrap_or(true);

    let pass = scenarios_ok && passive_ok && probe_ok;

    let summary = format!(
        "transport={} scenarios={}/{} passed{} | passive: {} flows, {} flagged (across {} profile report(s)) | active probe: {} | verdict={}",
        cli.transport,
        scenarios.iter().filter(|s| s.ok).count(),
        scenarios.len(),
        if failed_scenarios.is_empty() {
            String::new()
        } else {
            format!(" (failed: {})", failed_scenarios.join(","))
        },
        passive_total_flows,
        passive_flagged_flows,
        passive_reports.len(),
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
