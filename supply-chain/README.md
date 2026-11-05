# Dependency source assurance

This project uses cargo-vet **0.10.3**, exact registry checksums, immutable upstream audit snapshots, and a project-specific policy guard for every Cargo workspace. The strict audit gate is intentionally **failing** until missing reviews are completed. There are **zero exemptions** and no publisher/wildcard trust. Passing the policy tests does not mean the dependency graph is audited.

An initial proposal to grandfather the existing graph with broad exact-version exemptions was rejected by automatic approval review because that would grant audit criteria without source review. The implemented fallback grants no such criteria. `audit-debt.json` inventories missing reviews only; it is never loaded as an authorization or used to turn a cargo-vet failure into success.

## Scope and current debt

| Workspace | Required criteria | Registry versions | Missing required audits |
| --- | --- | ---: | ---: |
| root (`Cargo.toml`) | safe-to-deploy; dev-only safe-to-run | 191 | 183 |
| fuzz | safe-to-run | 163 | 136 |
| ci/gfw-lab | safe-to-run | 47 | 35 |
| verification/concurrency | safe-to-run, both optional backends | 69 | 60 |
| verification/sanitizers | std-only, unpublished fixture | 0 | 0 |

Counts are a 2026-11-05 snapshot, not a claim about future revisions. The emitted report is authoritative for a given checkout and contains exact package versions, missing criteria, lock digests, and the raw cargo-vet result. The sanitizer exclusion is checked against both its manifest and lock; adding any third-party or path dependency fails inventory validation.

## Run locally

```sh
cargo install --locked --version 0.10.3 cargo-vet
python3 scripts/security/dependencies.py policy
python3 .github/scripts/test_dependency_policy.py
python3 scripts/security/dependencies.py check --report target/security/dependency-report.json
```

The last command fetches Cargo sources with `--locked`, then runs cargo-vet with `--locked --frozen --no-minimize-exemptions --no-registry-suggestions` for all four graphs. It writes results after each workspace, continues collecting evidence across missing audits, and exits nonzero if any workspace fails. It checks that manifests, Cargo locks, and audit stores were not modified. `--vet-bin PATH` permits an explicitly installed tool outside PATH; `--base <40-character SHA>` additionally checks prior import trust on PRs.

CI separates policy/unit correctness from the strict source-audit result. No `continue-on-error`, automatic exemption generation, or blanket publisher trust masks missing reviews. cargo-deny separately checks advisories, source restrictions, licenses, and duplicate versions across all four graphs and all features. Existing advisory exceptions remain scoped to previously documented unmaintained crates; this change adds no vulnerability suppression. NCSA is allowed for libfuzzer-sys's bundled LLVM fuzzer; first-party license metadata matches the repository's existing PolyForm license.

## Imported evidence and local work

Google snapshot: `8cec794c38751495cf7a6c083220c207af1303d6`. Mozilla snapshot: `4716047f88d72d0685224af330bf21d0c2435b69`. URLs in every config use these full commit IDs. Selected full/delta audit records are preserved in each `imports.lock`, with their original reviewer attribution and notes. The guard pins the resulting lock bytes and, with `--base`, compares them byte-for-byte with the base store; updating the current digest alongside a replacement snapshot cannot bypass that comparison. Snapshot migrations require separate security policy review. These are inherited review statements, not reviews performed by this implementation team.

Root imports Google only, with no `imports.exclude` setting. Mozilla is deliberately absent from the root trust set because its `unicode-xid` publisher wildcard would apply there; cargo-vet 0.10.3 exclusions remove full audits but cannot remove wildcard audits. Fuzz and lab exclude the `unicode-xid` full audits; concurrency has no exclusion. All four committed import stores contain only selected full/delta records. The guard recursively rejects wildcard/publisher entries in the actual store, as well as criteria remapping, local criteria overrides, unknown registries, untracked workspace additions, policy lowering, and every exemption.

The local [untrusted 0.9.0 analysis](reviews/untrusted-0.9.0.md) is a bounded, explicitly AI-attributed compiled-source inspection. Its initial safe-to-run audit record was withdrawn pending independent human source review. The note grants no cargo-vet criteria and does not close either safe-to-run or safe-to-deploy gaps, review untrusted 0.7.1, or validate native crypto.

## Completing the audit backlog

Use cargo-vet's inspect/diff/suggest commands in a review branch. Read the full new crate or the complete delta from an accepted prior version, including build scripts, procedural macros, native code, generated artifacts, dependencies and enabled features. Record the exact version/delta, reviewer identity, criteria, and substantive evidence in `audits.toml`; link a review note where needed. Run the frozen checker after every change. A successful test or vulnerability scan is not a source audit.

Refreshing imports requires deliberate review of both the pinned upstream commit and selected audit statements, regeneration outside CI, and an explicit update of the import-lock digests in the guard. Policy changes require maintainer review; do not weaken the checks to make the graph green. Repository branch protection and reviewer independence are administrative controls outside this script.

References: [cargo-vet configuration](https://mozilla.github.io/cargo-vet/config.html), [criteria](https://mozilla.github.io/cargo-vet/built-in-criteria.html), [CI guidance](https://mozilla.github.io/cargo-vet/configuring-ci.html), [NCSA terms](https://spdx.org/licenses/NCSA.html).
