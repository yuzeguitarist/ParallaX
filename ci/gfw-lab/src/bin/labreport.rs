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
    /// Negative-control box report: known-bad flows that the analyzer MUST flag.
    #[arg(long)]
    control_report: Option<PathBuf>,
    /// Minimum flows the control must flag for the detector to be trusted.
    #[arg(long, default_value_t = 2)]
    min_control_flagged: usize,
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

    // Negative control: the SAME analyzer, run over deliberately-detectable
    // flows (a random/obfuscated tunnel + a plaintext tunnel), MUST flag them.
    // This proves the detector has teeth and is not rigged to always pass — if
    // the control is not flagged, the whole verdict is meaningless, so FAIL.
    let control: Option<GfwBoxReport> = match &cli.control_report {
        Some(p) => Some(load(p)?),
        None => None,
    };
    let control_flagged = control.as_ref().map(|c| c.flagged_flows).unwrap_or(0);
    // The control must exercise BOTH detection paths, so that neutering EITHER
    // one is caught: the structural "not a TLS record" check AND the
    // Frolov-Wustrow "fully encrypted" entropy classifier. Requiring the
    // specific flags (not just a total count) means a regression that disables
    // only the entropy test — while the trivial not-TLS check still fires — is
    // still detected as "detector lost teeth" and FAILS the run.
    let control_flag_present = |flag: &str| -> bool {
        control
            .as_ref()
            .map(|c| {
                c.flows
                    .iter()
                    .any(|f| f.verdict.flags.iter().any(|x| x == flag))
            })
            .unwrap_or(false)
    };
    let control_catches_structural = control_flag_present("first_flight_not_tls_record");
    let control_catches_entropy = control_flag_present("fully_encrypted_first_packet");
    let control_ok = match &control {
        Some(_) => {
            control_flagged >= cli.min_control_flagged
                && control_catches_structural
                && control_catches_entropy
        }
        // No control provided: cannot vouch for the detector -> do not pass.
        None => false,
    };

    // Pass policy — ALL must hold (each is a hard, non-vacuous requirement):
    //   * at least one scenario ran and every scenario completed (ok == true),
    //   * the passive middle-box actually analysed ParallaX flows AND flagged
    //     ZERO of them as a proxy (across ALL profiles),
    //   * the active differential prober ran and found NO distinguisher, AND
    //   * the negative control proved the detector has teeth on BOTH paths.
    let scenarios_ran = !scenarios.is_empty();
    let scenarios_ok = scenarios_ran && scenarios.iter().all(|s| s.ok);
    let failed_scenarios: Vec<&str> = scenarios
        .iter()
        .filter(|s| !s.ok)
        .map(|s| s.scenario.as_str())
        .collect();
    // Non-vacuous: require that flows were actually analysed, not just "0 of 0".
    let passive_ok = passive_total_flows > 0 && passive_flagged_flows == 0;
    // Non-vacuous: the probe must have run (absent probe is NOT a free pass).
    let probe_ok = probe
        .as_ref()
        .map(|p| !p.any_distinguisher)
        .unwrap_or(false);

    let pass = scenarios_ok && passive_ok && probe_ok && control_ok;

    let summary = format!(
        "transport={} scenarios={}/{} passed{} | passive: {} ParallaX flows, {} flagged (across {} profile report(s)) | control: {} known-bad flows flagged (detector {}) | active probe: {} | verdict={}",
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
        control_flagged,
        if control_ok { "HAS TEETH" } else { "NOT VALIDATED" },
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
        control,
        detector_has_teeth: control_ok,
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
