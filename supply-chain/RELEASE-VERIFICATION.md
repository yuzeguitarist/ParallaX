# Release provenance and SBOM verification

The release workflow builds Linux x86_64, macOS ARM64, and macOS x86_64 binaries on native hosted runners. A release tag must be a strict version tag. A manual dispatch must select that same tag as the workflow ref; dispatching main with an old-tag input is rejected. The checked-out commit, peeled tag commit, and event SHA must agree.

## Gates and trust boundaries

A strict cargo-vet source-audit job must pass before release builds. Current missing audits therefore block genuine signing and publication. The read-only package smoke job in `dependency-assurance.yml` remains available on PRs and security branches to validate packaging independently.

Build jobs have read-only repository access and no OIDC signing permission. They compile locked native binaries, strip the final copies, prefetch the entire locked Cargo graph (including metadata-only dev/other-target packages), then generate target-specific CycloneDX 1.5 SBOMs offline. Any Cargo.lock change is fatal. Every binary SBOM names its final executable SHA-256, exact source SHA/ref, target, Cargo package version, and a canonical UUID serial derived from source/target/binary/digest. The serial is required by the pinned attestation action, although cargo-cyclonedx 0.5.9 omits it. The manifest hashes both final binaries, both SBOMs, native inventory, archive, and checksum file. The archive includes README, LICENSE, and NOTICE.

Separate attestation jobs have no checkout and run no Cargo or downloaded executable. A fixed inline validator rejects unexpected files, symlinks, oversized data, duplicate JSON keys, mismatched metadata, unsafe archive paths/types/modes, and archive bytes that differ from the SBOM-bound binaries. It also enforces bounded, typed component arrays with unique registry references and source checksums; a complete rooted dependency graph with valid references; exact source, target and coverage properties; linked-library inventories for both binaries; and AWS-LC/ring versions and checksums that agree across both SBOMs and the native inventory. It inspects bounded tar data without extracting it. This is an explicit producer contract, not a full CycloneDX schema audit or proof that a compromised builder reports its components truthfully. Only then does the pinned GitHub attestation action create SLSA provenance and a separate SBOM attestation for each executable.

The publisher has no OIDC permission and no source checkout. It waits for every target, verifies every provenance subject and each binary SBOM attestation against the repository, workflow, tag, exact source digest, and hosted-runner requirement, then rechecks the remote tag. It creates a draft release with all assets and publishes after successful upload. Existing releases are never overwritten. A failed upload leaves a draft for maintainer inspection; retries do not clobber it.

This targets the GitHub-hosted signed provenance properties associated with SLSA Build L2. Job separation alone does not establish L3, hermetic builds, reproducibility, a trustworthy maintainer account, or audited dependencies. Tag/branch protection, required independent review, and protected publication administration remain repository-owner responsibilities.

## Verify before installing

Obtain the full expected source SHA from the reviewed release commit. Download the archive, target SBOMs, native inventory, manifest, and three `.sigstore.jsonl` bundles from the release. Example variables below must be replaced with the release being verified:

```sh
REPO=yuzeguitarist/ParallaX
TAG=v0.1.0
TARGET=x86_64-unknown-linux-gnu
SOURCE_SHA=REPLACE_WITH_REVIEWED_40_CHARACTER_COMMIT
PREFIX=parallax-${TAG#v}-${TARGET}
gh attestation verify "$PREFIX.tar.gz" \
  --bundle "$PREFIX.provenance.sigstore.jsonl" --repo "$REPO" \
  --signer-workflow "$REPO/.github/workflows/release.yml" \
  --source-ref "refs/tags/$TAG" --source-digest "$SOURCE_SHA" \
  --deny-self-hosted-runners
```

After archive verification succeeds, unpack it and verify the executable against its corresponding SBOM bundle:

```sh
tar -xzf "$PREFIX.tar.gz"
gh attestation verify "$PREFIX/parallax" \
  --bundle "$PREFIX.parallax.sbom.sigstore.jsonl" --repo "$REPO" \
  --predicate-type https://cyclonedx.org/bom \
  --signer-workflow "$REPO/.github/workflows/release.yml" \
  --source-ref "refs/tags/$TAG" --source-digest "$SOURCE_SHA" \
  --deny-self-hosted-runners
```

Repeat for `plx`; use the provenance bundle to verify the manifest and SBOM files too. A bare `.sha256` file detects accidental corruption but does not authenticate an origin. Do not accept a different source SHA solely because a mutable tag now points there. GitHub CLI verification may need network access to trust material; providing a bundle is not an offline-verification guarantee.

## Coverage limits

The Cargo SBOM covers default release features for the native target, including build dependencies and excluding dev-only dependencies. The accompanying native inventory records dynamically linked library names and the registry checksums of the AWS-LC and ring source bundles. Internal native subcomponents are not individually enumerated, and installed OS/SDK library versions are not asserted. These gaps are explicit in every BOM/manifest/native inventory. The toolchain and cargo-cyclonedx versions are recorded, but the build is not claimed reproducible.

The pinned cargo-cyclonedx 0.5.9 installation uses its upstream Cargo.lock, which currently warns about yanked xml-rs 0.8.19. This is a build-tool dependency, not a ParallaX runtime dependency; generated output is JSON and validated before privileged use. The warning is retained rather than hidden by an unlocked resolution. Re-evaluate the tool when upstream publishes a suitable pinned update.

Local dry-run after a locked native release build:

```sh
cargo install --locked --version 0.5.9 cargo-cyclonedx
python3 scripts/security/release_artifacts.py --tag "$TAG" --target "$TARGET" --commit "$SOURCE_SHA" --output "target/release-smoke/$TARGET"
python3 .github/scripts/test_release_workflow.py validate-artifacts --directory "target/release-smoke/$TARGET" --tag "$TAG" --target "$TARGET" --commit "$SOURCE_SHA"
```

References: [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations), [gh attestation verify](https://cli.github.com/manual/gh_attestation_verify), [SLSA build requirements](https://slsa.dev/spec/v1.2/build-requirements).
