# ConUnit: Developer Guide

This document gives the context of the ConUnit research project: what the tool is for, how it is built, what is implemented and where the evaluation protocol lives, so that an incoming researcher or contributor can work with the code. It states no evaluation result. Results exist only for a tagged final run and are generated from its files (see section 5).

---

## 1. Project Mission and Thesis

### The Problem
Container images (OCI specification) are the compilation target of cloud-native computing, and checking their quality is spread over several kinds of tools:
1. **Dockerfile linters (for example Hadolint)** read the Dockerfile text. They do not see the layers of an image built without a Dockerfile (Nix, Bazel, Jib, Buildpacks).
2. **Image linters (for example Dockle and the Anchore CIS policy pack)** inspect the configuration, the history and the filesystem of a built image. Much of the static ground of ConUnit's Tier 1 and Tier 2 overlaps with them, and the paper claims no novelty for it.
3. **Scanners (for example Trivy and Grype)** match installed packages against vulnerability databases, and some also scan configuration.
4. **Structure testers (Google container-structure-test, Goss)** check a declared structure with YAML specifications.

ConUnit adds a programmable test API in Go, a three-state outcome model (PASS, FAIL, UNVERIFIED, with a reason and evidence), and baseline-controlled differential probing at run time (Tier 3). Which of these claims the evaluation supports is stated in `docs/ANALYSIS_PLAN.md`.

### The Idea
An OCI container image can be treated as an **executable compilation unit** and tested like one, in the style of xUnit, across four tiers:
- **Tier 1 (Specification Invariants)**: Metadata contracts (non-root UID, deterministic entrypoints, sanitized environment).
- **Tier 2 (Filesystem and Artifact Hygiene)**: Layer composition (cache elimination, compiler exclusion, SUID/SGID bits).
- **Tier 3 (Dynamic Execution Contracts)**: Runtime behavior under a restriction (graceful `SIGTERM` handling, running under `--read-only`, running under `--cap-drop=ALL`), judged against a baseline run without the restriction.
- **Tier 4 (Supply Chain Integrity)**: SBOM-backed package presence or absence and license compliance. In the paper, Tier 4 is an interface only and is not evaluated.

---

## 2. System Architecture

```
                                 +-------------------------------------+
                                 |         Developer / CI Entry        |
                                 +------------------+------------------+
                                                    |
                         +--------------------------+--------------------------+
                         |                                                     |
                         v                                                     v
          +-----------------------------+                       +-----------------------------+
          |      Go Programmatic DSL    |                       |      CLI Pack Runner        |
          |       (tests/container_*.go)|                       |    (cmd/con-unit, pkg/runner)
          +--------------+--------------+                       +--------------+--------------+
                         |                                                     |
                         +--------------------------+--------------------------+
                                                    |
                                                    v
                               +----------------------------------------+
                               |              Core Engine               |
                               +--------------------+-------------------+
                                                    |
            +---------------------------------------+---------------------------------------+
            |                                                                               |
            v                                                                               v
+-----------------------+                                                       +-----------------------+
| Streaming OCI Reader  |                                                       | Dynamic Runtime Engine|
| (pkg/oci via Crane)   |                                                       | (pkg/engine via Podman|
| - Manifest inspection |                                                       | - Read-Only Rootfs    |
| - Layer tar indexing  |                                                       | - Drop Capabilities   |
| - Whiteout and links  |                                                       | - SIGTERM Trap Timing |
| - No layer extraction |                                                       | - Temp Graphroot      |
+-----------------------+                                                       +-----------------------+
            |                                                                               |
            +---------------------------------------+---------------------------------------+
                                                    |
                                                    v
                               +----------------------------------------+
                               |           Reporters & Outputs          |
                               |  - Console ([SUCCESS] / [FAILURE])     |
                               |  - Standard JUnit XML (<testsuites>)   |
                               |  - Empirical JSON Summary Matrix       |
                               +----------------------------------------+
```

### Key Architectural Pillars

1. **Streaming Daemonless Reading (`pkg/oci`)**:
   Powered by `github.com/google/go-containerregistry`. For Tiers 1 and 2, ConUnit reads the layers of an image as a tar stream, resolves whiteouts (`.wh.<file>`) and hard links, and records the properties it needs without extracting any layer. The layers come from a registry, from an image tarball, or, for an image in the local engine store, from a temporary docker-archive that `save --format docker-archive` writes and that is removed after the run. No claim is made about speed relative to other approaches. Timings are measured by `tools/benchmark_rq3` on a host that the run records.
2. **Dynamic Contract Harness (`pkg/engine`)**:
   For Tier 3 checks requiring process execution, ConUnit orchestrates ephemeral containers with strict isolation (`--read-only --tmpfs /tmp`, `--cap-drop=ALL`). Each treatment is compared with a baseline run that has only the defensive flags (`--network=none`, `--pids-limit=256`).
3. **Host Storage Policies (`pkg/conunit/storage.go`)**:
   Provides three storage policies:
   - `StoragePreserve`: Reuses cached local images (fast for iteration).
   - `StorageEphemeral`: Removes only images newly pulled by this run; it does not remove pre-existing images or globally prune the image store.
   - `StorageIsolatedTempRoot`: Uses an isolated `/tmp/conunit-graphroot-*` directory that is removed during cleanup.
   - **Panic and Signal Trap**: Catches `SIGINT` / `SIGTERM` to ensure cleanup runs even on unexpected termination.
4. **Pre-Packaged Rule Packs (`pkg/conunit/packs.go`)**:
   Composable rule bundles (`ProductionHygiene()`, `DistrolessHardening()`, `CISBenchmark()`, `KubeHardened()`, `NIST_SP_800_190()` and the static `ImageLint()`, selected with `--pack lint`) with fluent exclusion and whitelist APIs. `CISBenchmark()` is the ConUnit hardening profile, informed by a selected subset of the CIS Docker Benchmark. It is not the full benchmark and not a compliance attestation. The rule reference `docs/RULES.md` is generated from the code and states, per check, the standard control it maps to, how close the mapping is, and what the check cannot establish. Port checks inspect image-declared `ExposedPorts` only; they do not discover runtime listeners or published ports.
5. **Host Security and Defensive Sandboxing (`pkg/engine/engine.go`)**:
   When evaluating untrusted or mined container images, ConUnit protects the host system against hostile payloads via four defense mechanisms:
   - **Network Sandboxing (`--network=none`)**: Blocks outbound C2, network scanning, and cloud metadata probing (`169.254.169.254`) on all execution contracts.
   - **Fork-Bomb & RAM Defense (`--pids-limit=128 --memory=512m`)**: Caps process creation and memory allocation to eliminate host kernel starvation.
   - **Flag Injection Prevention (`ValidateImageRef` + `--`)**: Strictly validates image references against hyphen prefixing and uses `--` argument termination to neutralize malicious image names (e.g. `--privileged`).
   - **Decompression Bomb Protection (`MaxIndexedFiles=1000000` with an estimated memory budget, and `io.LimitReader`)**: Guards the tar stream analysis against archive expansion attacks.

### Evidence and Result Semantics

ConUnit distinguishes `PASS`, `FAIL`, and `UNVERIFIED`. A pass requires complete evidence for the check. A measured policy violation is a failure. Missing, malformed, ambiguous, unsupported, truncated, or unavailable evidence is unverified, never a pass. The `test` and `eval` commands return a nonzero status when any result is failed or unverified. JUnit reports represent unverified assertions as skipped and include the explicit outcome property.

The runner selects the platform reported by the container engine, checks it against the OCI image configuration, and compares the engine image ID with the OCI config digest. Reports record the resolved manifest digest, config digest, and platform at suite and assertion level. Runtime probes and Syft use the config digest as the image reference. Signature verification uses the repository reference pinned to the resolved manifest digest. Identity or platform mismatches stop evaluation instead of allowing mixed evidence.

Evidence scope and limits:
- **Filesystem indexing**: The index is limited to 1,000,000 entries and an estimated memory budget that follows from that cap. Exceeding either limit aborts indexing; partial findings are not reported as a pass.
- **Hard links**: A hard link takes the mode, owner and key-scan result of the file it names in the same layer. A link without such a target is unresolved, and a check that found nothing is then unverified.
- **Account checks**: Named users are resolved from the final image `/etc/passwd`. Blank-password checks use the final `/etc/passwd` and `/etc/shadow` files. Missing, malformed, ambiguous, or over-limit evidence is unverified. Each account file is limited to 1 MiB.
- **Private-key check**: The scan examines files whose basename ends in `.key` or `.pem`, plus `id_rsa`, `id_ed25519`, `id_dsa`, and `id_ecdsa`. It identifies PEM blocks whose type ends in `PRIVATE KEY`, including `OPENSSH PRIVATE KEY`. It does not search arbitrary filenames or non-PEM encodings. Candidate files with unsupported content or more than 1 MiB are unverified. A pass only means no supported private-key block was found in the completely scanned candidates.
- **ADD history check**: Missing or malformed OCI history is unverified. A pass means no prohibited `ADD` was found in the usable recorded history. OCI history can omit build steps, so this check does not prove the source Dockerfile used only `COPY`.
- **Signature check**: The CIS-informed pack reports signature status as unverified unless a verifier and trust policy are configured. The CLI accepts either `--cosign-key` or both `--certificate-identity` and `--certificate-oidc-issuer`. Cosign verifies the resolved manifest digest, not a mutable tag.

---

## 3. Directory Layout

```
.
├── cmd/
│   └── con-unit/               # CLI entrypoint (test, eval, rules, version)
├── docs/
│   ├── ANALYSIS_PLAN.md        # Evaluation protocol, decision rules, pilot and freeze
│   ├── CONTRACT.md             # Shared interfaces: result document, flags, files
│   ├── DEVIATIONS.md           # Log of changes to the evaluation design after the first version of the plan
│   ├── INTERFACE_V2.md         # Interface of the evaluation tools (version 2)
│   └── RULES.md                # Rule reference, generated from the code
├── fixtures/
│   ├── archetypes.json         # Archetype and base family per repository
│   ├── evaluation_dataset_*    # Candidate and digest-pinned evaluation images
│   └── rq1/                    # Defect-seeded corpus and ground-truth oracle
├── pkg/
│   ├── conunit/                # The Go Programmatic DSL, lifecycle, rule packs, storage
│   ├── engine/                 # OCI container engine abstraction (Podman/Docker)
│   ├── oci/                    # Daemonless streaming layer inspector
│   ├── reporter/               # Console, JUnit XML, and JSON reporters
│   ├── runner/                 # CLI pack runner
│   └── spec/                   # Shared type definitions (Tier, Suite, TestCase, Result)
├── tools/                      # Evaluation tools (rq1, benchmark_rq3, exporter, adjudication, ...)
├── reports/                    # Generated JUnit XML test reports
├── results/                    # Evaluation outputs (JSON matrix + Markdown summary)
├── tests/
│   └── container_test.go       # End-to-end programmatic Go test demonstration
├── flake.nix                   # Nix flake dev shell (Go, Just, Syft, Grype, Hadolint, Trivy, container-structure-test)
├── justfile                    # Automated reproducible workflows
└── ONBOARDING.md               # This guide
```

The paper and the AWS evaluation pipeline live in the separate `submission` repository.

---

## 4. Quick Start

### Prerequisites
This project uses **Nix flakes**. If `direnv` is enabled, entering the directory loads the complete environment automatically:

```sh
cd path/to/con-unit
# The environment loads automatically with the Go toolchain, Just and the comparison tools
```

### Essential Commands
All workflows are automated via `just`:

```sh
# 1. Run offline-safe unit tests (no local engine or image pulls)
just test

# 2. Opt in to engine-backed tests (requires a local engine; tests may pull images)
just test-integration

# 3. Compile the standalone CLI binary
just build

# 4. Test a single image via CLI using the CIS-informed hardening profile
./bin/con-unit test alpine:latest --format console

# 5. Test with a specific pack (e.g. hygiene, kube, nist, distroless)
./bin/con-unit test alpine:latest --pack hygiene

# 6. Generate standard JUnit XML report
./bin/con-unit test python:3.11-slim --format junit --output reports/python-junit.xml

# 7. Run the engine-backed programmatic Go DSL test
CONUNIT_INTEGRATION=1 go test -v ./tests

# 8. Run an evaluation over the 10-image pinned subset (a pilot, not a result)
just eval-top10
```

---

## 5. Results

This repository contains no evaluation result. Earlier smoke runs on a few images came from earlier versions of the tool and are not evidence, so they are not reproduced here. The numbers of the paper are generated, by `tools/export_latex.go` and the other evaluation tools, from the files of a final run that starts from the tag `eval-v1`. The protocol, the decision rules and the rule for pilot runs are in `docs/ANALYSIS_PLAN.md`.

---

## 6. Evaluation

- The evaluation protocol is `docs/ANALYSIS_PLAN.md`. Changes to the design after its first version are logged in `docs/DEVIATIONS.md`.
- The interfaces that the evaluation tools share (file names, flags, stages, macro names, table labels) are in `docs/INTERFACE_V2.md` and `docs/CONTRACT.md`.
- A pilot on a subset may fix check bugs before the freeze, and its output is never used in the paper. The final run starts from a tagged commit.
