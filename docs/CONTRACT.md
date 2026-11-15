# ConUnit Shared Contract

This document fixes the interfaces between the parts of the system. Types live in `pkg/spec/contract.go` and `pkg/spec/types.go`.

## 1. Result document

`con-unit eval` writes `<out-dir>/empirical_study.json` as a `spec.Study`:

- `schema_version`: `spec.SchemaVersion` (currently "2").
- `run`: `spec.RunMetadata`, filled by `runenv.Detect`. Facts are detected, never assumed. In particular `execution_mode` and `virtualization` are derived from DMI data, AWS instance metadata (IMDSv2, short timeout) and the engine, never from the operating system name alone.
- `images`: one `spec.SuiteResult` per attempted image. Every attempted image has exactly one record.

The earlier array-only format is no longer written. Readers may still decode it for old artifacts.

### Image record

- `requested_ref`: the reference as given. `image_name` equals it.
- `image_source`: `local-store`, `registry` or `tarball`.
- `image_digest`: the registry digest of the requested image. It is taken from the digest-pinned input and verified against the engine's `RepoDigests`. A digest synthesized from a local archive must never be reported as the registry digest.
- `config_digest`: the image config digest, checked against the engine's image ID.
- `status`: one of `spec.Status*`. `reason`: a `spec.Reason*` for non-COMPLETED statuses.
- A non-COMPLETED record keeps `image_digest`, `config_digest`, `platform` and `resources` (`layer_count`, `compressed_bytes`, `uncompressed_bytes`, `indexed_entries`) when they were known at the failure. For INDEX_LIMIT the last two are lower bounds.
- `resources.peak_rss_mb` is a ceiling of the whole process, never a per-image value. Consumers use only its maximum over the batch. `live_heap_mb`, `self_cpu_seconds` and `child_cpu_seconds` describe the ConUnit process only, never the engine or the probe containers. `compressed_bytes` is filled only for the registry source. `uncompressed_bytes` is the content bytes scanned. `platform` includes the variant when known (for example `linux/arm64/v8`).

### Result record

- `outcome`: PASS, FAIL or UNVERIFIED. `reason` qualifies UNVERIFIED (and FAIL where needed).
- `evidence`: observations behind the outcome (baseline and treatment states, exit codes, log tail, finding paths).
- `hint`: keyword-derived suggestion, never a root-cause claim, never used by the exporter.
- `rule`: standard mapping (`standard`, `standard_version`, `control_id`, `mapping`, `scope`). The exporter derives its "standard" column from this.
- Invariant: at most one result per `test_id` per image, with a stable `test_name` per ID.

## 2. Status and reason vocabularies

Statuses: COMPLETED, TIMEOUT, UNAVAILABLE, RATE_LIMITED, INDEX_LIMIT, EXECUTION_ERROR, EXCLUDED.

Tier 3 reasons: BASELINE_FAILED, NOT_OBSERVABLE, PROBE_TIMEOUT, PROBE_ERROR.
Evidence reasons: EVIDENCE_INCOMPLETE, NO_TRUST_POLICY, TOOL_UNAVAILABLE, FILE_MISSING.
Image-level reasons: REGISTRY_THROTTLED, MANIFEST_NOT_FOUND, IDENTITY_MISMATCH, PLATFORM_MISMATCH, DEADLINE_EXCEEDED, INDEX_TOO_LARGE.

Status classification uses typed errors, never substring matching of error text.

## 3. CLI flags

`eval`:

- `--images <file>`: newline-delimited image references.
- `--pack <name>`: default `cis`. The `cis` name stays as an alias of the CIS-informed hardening profile. The name `lint` (alias `image-lint`) selects the static image lint pack, which needs no engine and starts no container.
- `--out-dir <dir>`: default `results`.
- `--engine auto|podman|docker`: default `auto`.
- `--platform <os/arch>`: passed explicitly to pull and inspect. Default is the host platform. The AWS run uses `linux/amd64`.
- `--image-source auto|local|registry`: default `auto`, which prefers the engine's local store and falls back to the registry only if the image is absent from the store. `local` fails if the image is absent from the store.
- `--probe-window <duration>`: Tier 3 observation window W, default `3s`.
- `--image-timeout <duration>`: per-image deadline, default `5m`.
- `--max-index-entries <n>`: default 1000000. Caps the entries of the filesystem index and implies an estimated memory budget of n x 768 bytes (512 per entry plus an average path allowance of 256 bytes), checked per layer and on the merged view. An image above either limit is recorded as INDEX_LIMIT with reason INDEX_TOO_LARGE.
- `--journal <path>`: default `<out-dir>/journal.jsonl`.
- `--resume`: skip images that already have a COMPLETED record in the journal. Other statuses are retried.
- `--fail-on-findings`: exit 1 when any FAIL or UNVERIFIED result exists. Off by default.
- `--cosign-key`, `--certificate-identity`, `--certificate-oidc-issuer`: unchanged.

`test` gains `--platform`, `--image-source` and `--probe-window` with the same meaning and keeps its CI-gate exit behavior.

## 4. Exit codes

`spec.ExitOK` (0), `spec.ExitFindings` (1), `spec.ExitUsage` (2), `spec.ExitIncomplete` (3).

`eval` returns 0 when every attempted image produced a COMPLETED record, regardless of findings. It returns 3 when any image ended in another status or an output file could not be written. It returns 2 for invalid flags. It returns 1 only with `--fail-on-findings` and findings present.

## 5. Journal

`<out-dir>/journal.jsonl` is append-only JSON Lines. Each line is one `spec.SuiteResult`, appended and flushed after the image finishes. The last record per `requested_ref` wins. The study document is assembled from the journal at the end of the run, so a crash never loses completed images. `benchmark_rq3` journals per trial in the same way.

## 6. Tier 3 semantics

For each image the runner first starts a baseline container with only the defensive flags (`--network=none`, `--pids-limit=256`, mock environment variables) and observes it for W.

- Baseline start failed or exited non-zero: all Tier 3 results are UNVERIFIED with reason BASELINE_FAILED.
- Baseline exited 0 before W: UNVERIFIED with reason NOT_OBSERVABLE.
- Baseline running at W: each treatment (read-only rootfs, cap-drop, no-new-privileges, 256 MiB memory limit) runs with the same defensive flags plus the treatment flag. PASS if the container is running at W. FAIL otherwise, with exit code, state and log tail in `evidence`.

Tier 3 latency is bounded below by W and must not be presented as a performance result.

## 7. Output file names

Written by `con-unit eval`: `empirical_study.json`, `EMPIRICAL_SUMMARY.md`, `ATTRITION_REPORT.md`, `journal.jsonl`, `logs/`.

Written by `tools/export_latex.go` from `empirical_study.json`: `table_rq2_prevalence.tex`, `table_rq3_phases.tex`, `macros_study.tex`, `fig_rq2_prevalence.tex`, `fig_rq3_phase_breakdown.tex`, `fig_rq3_memory_scaling.tex`, `preview_paper.tex`. `fig_rq2_prevalence.tex` is a complete `figure` float with caption and label `fig:rq2_prevalence`: a forest plot at one column width that shows a visible pending frame while no headline check has a verified image. It needs only `\usetikzlibrary{patterns}` in the paper preamble, with `tikz` and `xcolor` loaded. The two RQ3 figures are bare pgfplots pictures and need `pgfplots` with `\pgfplotsset{compat=1.18}`.

Written by `tools/benchmark_rq3`: `rq3_telemetry.json` (with `run` as `spec.RunMetadata` and per-image trials), `RQ3_PERFORMANCE.md`, `table_rq3_trials.tex`, `macros_rq3.tex`. The Dockle timing (flag `-dockle`) and the Tier 3 floor are written to the same files.

No two tools write the same file name. Per-image macros are keyed by a sanitized image name.

## 8. Fixtures

- `fixtures/archetypes.json`: object keyed by repository name without registry (for example `nginx`), each value `{"archetype": "...", "base_family": "..."}`. Read by the exporter and the RQ3 benchmark. Substring inference is removed. The base families of the 26 pinned images that were `unknown` come from the os-release file of the image itself, with the raw evidence in `fixtures/base_family_evidence.json`.
- `fixtures/rq1/oracle.json`: ground truth for the seeded-defect corpus, with property, defect presence and the tools for which the property is in scope. Schema version 2 takes the scopes from the published catalogs of the pinned tool versions and carries a `source` per entry.
- `fixtures/rq1/tier3_truth.json`: the expected minimal cause of each seeded runtime defect, and whether the defect manifests on the engine (`manifests`, required).
- `fixtures/base_family_evidence.json`: per image the raw os-release text, the release marker files, the config digest and the rule that decided the base family. Written by `tools/label_base_family`, which can derive the families again from this file without a registry.

## 9. Registry source for the AWS run

Digest-pinned `docker.io/library/<name>@sha256:<digest>` references are fetched from `public.ecr.aws/docker/library/<name>` through a Podman registry remap. File `/etc/containers/registries.conf.d/50-conunit-mirror.conf`:

    [[registry]]
    prefix = "docker.io/library"
    location = "public.ecr.aws/docker/library"

This is a single remap with no Docker Hub fallback, so a mirror failure is loud. The dataset spells references as `index.docker.io/library/<name>@sha256:<digest>`, which Podman normalizes to `docker.io`. The canary run must confirm with `podman pull --log-level=debug` that the remap is applied (the debug log shows the `public.ecr.aws` location). Images keep their logical `docker.io` names. The remap is recorded in `run.registry_remap`: `con-unit eval`, `con-unit test` and `benchmark_rq3` all read it from the environment variable `CONUNIT_REGISTRY_REMAP`, which the AWS run sets to `docker.io/library -> public.ecr.aws/docker/library`, and the run block check of the AWS run fails when it is missing. `tools/check_mirror.sh` HEAD-checks every pinned digest on the mirror at 1 request per second or slower.

## 10. Pre-flight and tags

- The AWS bundle is built with `git archive <tag>`. The evaluation runs only from a tagged commit (`eval-v1` for the final run). `--allow-dirty` marks the run as tainted.
- Rule IDs emitted in results are the identifiers used for pack exclusions.

## 11. Addenda agreed during implementation (binding)

1. FS-06 and FS-07: the outcome is FAIL only when `evidence.paths` (non-fixture findings) is non-empty. Findings under fixture-like locations go into `evidence.fixture_candidate_paths`; if only those exist the outcome is PASS and the message states how many fixture candidates there are. Fixture-like locations: any path component in {testdata, test, tests, fixtures, fixture, examples, example}, plus the Debian snakeoil key basenames.
2. SIGTERM check (EXEC-03): exit code 0 or 143 within the timeout counts as terminated by SIGTERM. The exit code is recorded in the evidence.
3. UNVERIFIED caused by missing, truncated or unparsable evidence uses reason EVIDENCE_INCOMPLETE. SUP-02 without a trust policy uses NO_TRUST_POLICY, a missing external tool uses TOOL_UNAVAILABLE.
4. Emitted rule IDs are canonical. CIS-style handles (CIS-4.10 and so on) remain accepted for exclusions only.
5. Hardening profile: pack ID `PACK-CONUNIT-HARDENING` (it was `PACK-CIS-DOCKER` before schema version 2), display name `ConUnit Container Hardening Profile (CIS-informed)`, valid names `cis`, `cis-docker`, `cisbenchmark` and `hardening`. It holds 17 checks. `EXEC-03` and `FS-01` are in the `hygiene` pack, not in the profile. The rule catalog (oracle, evidence, limits, mapping) is `docs/RULES.md`, generated by `con-unit rules`.
6. `benchmark_rq3` flags: `-file`, `-pack`, `-out-dir`, `-iterations` (timed trials, default 10), `-warmup` (default 1), `-platform`, `-probe-window` (default 3s), `-engine`, `-image-source`, `-archetypes`, `-cold-trials`. Run it as the package `./tools/benchmark_rq3`. Its journal is `rq3_journal.jsonl`.
7. Exporter: `go run ./tools/export_latex.go [-out DIR] [-paper-dir DIR] [-audit FILE] [-headline FILE] [-archetypes FILE] [-check] [-list-outputs] <empirical_study.json>`. With `-paper-dir` all generated .tex files go to `<paper-dir>/results/`. It exits 3 when no image is COMPLETED, after writing its files.
8. Mirror check: `OUT_DIR=<dir> MIRROR_DELAY=<s> tools/check_mirror.sh <dataset-file>`, writes `mirror_check.json`, non-zero on any miss or digest difference.
9. LaTeX macro names contain letters only. For a rule ID the ID-key is the ID with hyphens and dots removed and digits spelled out (SPEC-01 becomes SPECZeroOne). Per check the exporter emits `\ConUnitPrev`, `\ConUnitPrevLo`, `\ConUnitPrevHi`, `\ConUnitFail`, `\ConUnitVerified`, `\ConUnitUnverified` followed by the ID-key, plus flow macros `\ConUnitNCandidates`, `\ConUnitNPinned`, `\ConUnitNAttempted`, `\ConUnitNCompleted`, `\ConUnitNAttrition` and environment macros `\ConUnitEnv...`. The complete list is in `tools/LATEX_INCLUSION_GUIDE.md`. Body tables carry the labels `tab:attrition`, `tab:rq2_prevalence`, `tab:rq3_phases`, `tab:rq1_detection`; the body figure written by the exporter carries `fig:rq2_prevalence`; artifact tables `tab:rq2_exploratory`, `tab:strata`, `tab:rq3_trials`, `tab:unverified`.
10. `fixtures/headline_checks.json` (keys `headline`, `exploratory`, `excluded`) decides which checks appear in the headline table. Unlisted IDs are exploratory with a warning.
11. RQ1 runner: `go run ./tools/rq1 -oracle fixtures/rq1/oracle.json -out-dir <dir> -conunit bin/con-unit`, outputs `rq1_results.json` and `table_rq1_detection.tex` (label `tab:rq1_detection`, a compact symbol matrix with light cell shading that needs `\usepackage[table]{xcolor}` and booktabs in the paper preamble). A tool that is absent is NOT_RUN, never silently skipped. Five tools run (Hadolint, Trivy, container-structure-test, Dockle and ConUnit), and a case that a tool did not evaluate is NOT_EVALUATED, never a detection and never a miss. The flags `-engine` and `-require-all` exist.
12. `runenv.BuildCommit` and `runenv.BuildTainted` are set with `-ldflags -X github.com/con-unit/con-unit/pkg/runenv.BuildCommit=<sha>` because the AWS bundle is built from a git archive that has no VCS metadata.
13. AWS result layout: `results/<RUN_ID>/` holds the eval outputs, exporter outputs, `eval.log`, `run_manifest.json`, `SHA256SUMS`, `status.json` and `BENCHMARK_COMPLETE`; `results/<RUN_ID>/rq3/` holds the RQ3 outputs.

## 12. Evaluation tools of version 2

The tools and files that were added for version 2 (the cross-check against Dockle, raw agreement, Tier 3 attribution with minimization, ablation, reliability, the `lint` pack, the base family labeling and the new stages of the AWS pipeline) are specified in `docs/INTERFACE_V2.md`. Its section 10 holds the binding amendments. This contract keeps the result document, the flags of `eval` and the exit codes as they are.

Output files by tool, so that no two tools write the same name:

- `tools/crosscheck`: `crosscheck.json`, `discordances.csv`, `table_crosscheck.tex`, `table_discordances.tex`, `macros_crosscheck.tex`, `table_coverage.tex` and `raw/`.
- `tools/agreement`: `agreement.json`, `table_agreement.tex`, `macros_agreement.tex`.
- `tools/attribute_exec`: `attribution.json`, `attribution.csv`, `ablation.json`, `table_attribution.tex`, `macros_attribution.tex`, all in one directory.
- `tools/reliability`: `reliability.json`, `table_reliability.tex`, `macros_reliability.tex`.
- `tools/adjudication`: `adjudication_template.csv`, `adjudication_summary.json` (schema 2, with a separate `crosscheck` section).

`tools/label_base_family` is a fixture tool and not a stage of the AWS run. The exit codes of these tools follow section 4. Exit code 3 means that outputs were written and some input was missing or failed.
