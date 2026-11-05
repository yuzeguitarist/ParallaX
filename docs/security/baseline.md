# OpenSSF Baseline mapping

Reference: [OSPS Baseline 2026.08.28](https://baseline.openssf.org/versions/2026-08-28).
This is a scoped engineering mapping, not a certification or a claim that every
control is satisfied. Evidence is specific to a revision and a completed run.

## Evidence and outstanding conditions

| Control references | Project evidence / condition |
| --- | --- |
| OSPS-BR-01.01, OSPS-BR-01.04 | Release input validation binds a restricted tag, event ref, event SHA and checked-out commit; subprocesses use explicit argument vectors. Workflow tests exercise hostile and mismatched inputs. |
| OSPS-BR-01.03 | PR checks have read-only tokens. Native release builds are separated from source-free signing/publishing. Artifact inputs are restricted to the expected files from the same workflow run. |
| OSPS-AC-04.01, OSPS-AC-04.02 | New workflows declare minimum permissions; OIDC/attestation rights are confined to the signing job. Repository defaults and other integrations need owner review. |
| OSPS-BR-02.01, OSPS-BR-02.02 | Release filenames, metadata and checksums carry the release tag and target. Existing assets cannot be silently overwritten. |
| OSPS-BR-06.01 | Final asset bytes receive GitHub build-provenance attestations; per-binary SBOM evidence is included. Operational evidence requires the first completed release using the new workflow and consumer verification. |
| OSPS-QA-02.01, OSPS-QA-02.02 | Locked manifests, target-specific CycloneDX documents and native dependency/linkage inventory. The SBOM scope is explicit; system SDKs and assembly are not represented as separately audited source. |
| OSPS-DO-03.01, OSPS-DO-03.02 | [Consumer verification](RELEASE-VERIFICATION.md) covers checksums, expected repository/workflow identity and provenance. A matching hash alone is insufficient. |
| OSPS-DO-06.01, OSPS-DO-07.01 | [Dependency policy](../../supply-chain/README.md), pinned tools and repository build instructions. Frozen audit imports and exact exemption ledgers separate review evidence from inherited debt. |
| OSPS-QA-06.01, OSPS-QA-06.02 | Existing tests plus bounded Loom/Shuttle, native sanitizer workloads, independent protocol oracles, fault injection and real-listener scenarios. [Commands and limits](README.md) and machine-readable reports describe actual execution. |
| OSPS-SA-01.01, OSPS-SA-02.01 | Existing SPEC/README describe the protocol; [design record](assurance-design.md) and [threat model](threat-model.md) identify product, experimental, host and release interfaces. |
| OSPS-SA-03.01, OSPS-SA-03.02 | Threat assessment, design review, separately staffed code review and local attack fixtures. External human penetration testing remains a separate deliverable requiring an assessor, agreed scope and a report. |
| OSPS-VM-05.01, OSPS-VM-05.02, OSPS-VM-05.03 | Dependency policy, cargo-deny and cargo-vet apply to enumerated Cargo workspaces. A vet exemption is not a vulnerability disposition, a source audit or VEX. Review enforcement ultimately depends on branch rules. |
| OSPS-VM-06.01, OSPS-VM-06.02 | Existing static-analysis workflows remain relevant; this change adds runtime and behavioral evidence. No blanket assertion about complete SAST policy or all historical findings is made. |
| OSPS-LE-03.01, OSPS-LE-03.02 | Existing LICENSE/NOTICE are retained and bundled with release assets. |
| OSPS-LE-02.01, OSPS-LE-02.02 | **Incompatible with the current noncommercial license.** The project deliberately retains its existing license and restrictions. Technical hardening does not change this result. |

The remaining organizational and lifecycle controls are not inferred from code.
In particular, an AI review does not satisfy the non-author **human** approval
condition in OSPS-QA-07.01.

## Repository-owner decisions

Review the actual repository settings and keep dated evidence for:

- OSPS-AC-01.01 / OSPS-AC-02.01: collaborator authentication and privilege grants.
- OSPS-AC-03.01 / OSPS-AC-03.02 / OSPS-QA-03.01 / OSPS-QA-07.01:
  protected primary branch, deletion protection, required status checks and
  non-author human approval, including bypass actors.
- OSPS-GV-01.01 / OSPS-GV-01.02 / OSPS-GV-04.01: accountable maintainers and
  escalation review.
- OSPS-BR-07.01 / OSPS-BR-07.02: secret scanning, credential ownership, storage
  and rotation procedures.
- OSPS-DO-04.01 / OSPS-DO-05.01: support and retirement policy.
- OSPS-LE-01.01: contribution authorization.
- OSPS-VM-01.01 through OSPS-VM-04.02: maintained disclosure process, contact
  response, advisory publication and evidence-backed non-exploitability records.
- OSPS-QA-06.03: review policy requiring tests for major changes.

These settings and policies are not changed by the security PR. Existing
SECURITY/CONTRIBUTING material should be evaluated against current operating
practice; file presence alone does not establish compliance.

## How to update this record

For each claimed control, attach the relevant commit, workflow run or release
verification result. Keep a failed or unexecuted check distinct from a passing
check; retain model bounds, test selections, sanitizer limitations and vet debt.
A release attestation authenticates recorded provenance and bytes; it is not a
security audit, reproducible-build proof or SLSA Build L3 certification.
