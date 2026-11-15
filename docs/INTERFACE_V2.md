# Interface of the evaluation tools (version 2)

This document fixes the names, files, flags, stages and schemas that the evaluation tools of this repository share, so that they compose. Section 10 holds binding amendments that supersede the text above it.

## 0. Conventions

- Results are TP, FP, FN, TN or OUT_OF_SCOPE, never a bare pass rate. The three-state outcome model (PASS, FAIL, UNVERIFIED) holds everywhere.
- Offline tests do not need an engine, a network or an installed external tool. Engine-backed tests are opt-in behind the existing environment switch.
- Logs are structured and easy to scan. Documentation and logs contain no emojis.

## 1. Repositories

The tools and their tests are in this repository. The paper and the AWS evaluation pipeline are in a separate repository, which keeps a copy of this document.

## 2. Naming rules shared by all generated LaTeX

- Macro names contain letters only. A rule ID key removes hyphens and dots and spells every digit: SPEC-09 is `SPECZeroNine`, FS-10 is `FSOneZero`, CIS-4.6 is `CISFourSix`.
- A table or figure file that a tool writes carries its own label. No two tools write the same file name.
- A value that is not available prints `n/a`. A committed placeholder prints `[pending]`.

## 3. The `lint` pack and eight new checks

Pack: ID `PACK-IMAGE-LINT`, display name `Image Static Lint Pack`, selectable with `--pack lint` and `--pack image-lint`. Static checks only: no Tier 3, no engine, no Syft. It must work on a `tarball`, `registry` and `local-store` image source. The 17-check hardening profile and the other packs stay unchanged, except that the shared FS-01 path list may gain one entry (see below).

Members, in execution order: SPEC-01, CIS-4.6, FS-04, SPEC-07, SPEC-03, FS-06, FS-08, FS-01, SPEC-09, SPEC-10, SPEC-11, SPEC-12, SPEC-13, FS-10, FS-11, FS-12.

New checks. All start exploratory. Mapping types are custom unless stated. Every check ends as PASS, FAIL or UNVERIFIED. Missing, empty or malformed evidence is UNVERIFIED with reason `EVIDENCE_INCOMPLETE`. Each check needs a catalog entry (`Name`, `Oracle`, `Evidence`, `Limits`, `Meta`) in the rule catalog.

- `SPEC-09` Update Instruction Combined With Install (Tier 1, history). FAIL when one recorded build step runs a package index update (`apt-get update`, `apt update`) and does not also run `install` or `upgrade` of the same manager later in that step. A custom ConUnit check, no CIS control number is stated (DEV-15). Dockle reference: CIS-DI-0007.
- `SPEC-10` No Sudo in the Build History (Tier 1, history). FAIL when `sudo` appears in command position of any recorded step. Dockle: DKL-DI-0001.
- `SPEC-11` No Distribution Upgrade in the Build History (Tier 1, history). FAIL when `apt-get dist-upgrade` or `apt dist-upgrade` is recorded. Dockle: DKL-DI-0003.
- `SPEC-12` No Sensitive Host Paths as Volumes (Tier 1, config). FAIL when the image config declares a volume at `/dev`, `/proc` or `/sys`, or below them. Dockle: DKL-DI-0002.
- `SPEC-13` Explicit Non-Latest Image Reference (Tier 1, requested reference). FAIL when the requested reference has no tag and no digest, or the tag is `latest`. PASS for a digest or any other explicit tag. Limits state that explicit tags stay mutable. Dockle: DKL-DI-0006.
- `FS-10` Unique Account and Group IDs (Tier 2). FAIL when two different account names share a UID in `/etc/passwd`, or two different group names share a GID in `/etc/group`. Needs `/etc/group` captured next to the other account files in `pkg/oci/reader.go` with the same size limit and evidence-issue handling. Dockle: DKL-LI-0002.
- `FS-11` No Development, Editor, Cache or Cloud Leftovers (Tier 2). FAIL when the merged filesystem contains a path component `.cache`, `.aws`, `.azure`, `.gcp`, `.git`, `.vscode`, `.idea` or `.npm`, or a file named `Dockerfile`, `docker-compose.yml`, `.vimrc` or `.DS_Store`. Subtrees below `node_modules` and `vendor` are skipped. Findings are reported once per directory. Dockle: DKL-LI-0003.
- `FS-12` No Credential-Named Files (Tier 2). FAIL on a file with one of the names `credentials.json`, `credential.json`, `credentials`, `credential`, `password.txt`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `secret_token.rb`, `carrierwave.rb`, `omniauth.rb`, `settings.py`, `database.yml`, `credentials.xml`, `.env`, or one of the extensions `.secret`, `.ovpn`, `.private_key`, `.cscfg`, `.rdp`, `.mdf`, `.sdf`, `.bek`, `.tpm`, `.fve`, `.jks`, `.psafe3`, `.agilekeychain`, `.keychain`, `.pcap`, `.gnucache`. Findings under the fixture-like components of FS-06 are fixture candidates, counted separately, and do not fail the check. A custom ConUnit check, no CIS control number is stated (DEV-15). Dockle: CIS-DI-0010 (file-name part).

Existing checks in the pack, with parameters:

- `SPEC-03` gets a second parameter, accepted keys, default empty. The `lint` pack uses disallowed keys `PASS`, `PASSWD`, `PASSWORD`, `SECRET`, `KEY`, `ACCESS`, `TOKEN` and accepted keys `GPG_KEY`, `GPG_KEYS`. Other packs keep their lists and behave as before.
- `FS-01` in the `lint` pack uses the hygiene paths plus `/var/lib/apt/lists`. The hygiene paths (`pkg/conunit/packs.go`) do not contain `/var/lib/apt/lists`, while the RQ1 oracle says ConUnit detects the property `apt-lists` through FS-01. The property therefore runs with pack `lint`.

Tokenizing rule for history checks: split a recorded command on `&&`, `||`, `;`, `|` and newlines, handle quotes and backslash continuations, and treat a word as a command only in command position (so `echo sudo` is no finding). Intended differences from Dockle are documented in each check's `Limits`.

Stage `lint`: `con-unit eval --images <eval dataset> --pack lint --out-dir <RESULTS_DIR>/lint --engine podman --platform linux/amd64 --image-source auto`, producing `<RESULTS_DIR>/lint/empirical_study.json`.

Required tests are listed in section 9.

## 4. RQ1 with Dockle

- New tool name `dockle` (Go constant `ToolDockle`), binary `dockle`, version probe `dockle --version`, flag `-dockle` for an explicit path, `-tools` accepts `dockle`. It runs from the same docker-archive export as Trivy (`save --format docker-archive`) with `dockle --input <archive> --format json --exit-code 0`, and a case counts as detected when the JSON `details` contain an entry whose `code` is in the property's `detect_ids`, at level INFO, WARN or FATAL, or at level SKIP with an alert that does not start with "failed to detect " (section 10, amendment A2). The archive's config digest is recorded in the raw run file.
- Oracle schema additions in `fixtures/rq1/oracle.json`: `tools` gains `dockle`. Every per-tool entry gains `source` (a URL or catalog identifier and the version it was read at). `in_scope` and `detect_ids` come from the published catalog of the tool at its pinned version, not from guesses. A tool that is out of scope is never counted as having missed.
- Properties that Dockle covers: root-user (CIS-DI-0001), no-healthcheck (CIS-DI-0006), setuid-binary (CIS-DI-0008), add-local-file and add-remote-url (CIS-DI-0009), secret-in-env and private-key-file (CIS-DI-0010), package-cache (DKL-DI-0004), apt-lists (DKL-DI-0005). Out of scope for Dockle: world-writable-file, privileged-port, shell-form-entrypoint, runtime-needs-capability.
- New properties, each with a defect case and a clean control, Dockerfiles on digest-pinned bases, no network at run time: `update-alone`, `sudo-usage`, `non-unique-uid` (ConUnit in scope with pack `lint`: SPEC-09, SPEC-10, FS-10), and the seeded runtime defects `needs-setuid-setgid`, `writes-outside-tmp`, `nonroot-privileged-port` (ConUnit in scope with pack `cis`: EXEC-02, EXEC-01, EXEC-02). The properties `package-cache` and `apt-lists` switch to pack `lint`.
- `fixtures/rq1/tier3_truth.json`:

```json
{
  "schema_version": 1,
  "image_prefix": "localhost/conunit-rq1",
  "cases": [
    {"case": "needs-setuid-setgid-defect", "rule": "EXEC-02", "expected_minimal": ["CAP_SETGID", "CAP_SETUID"], "manifests": true},
    {"case": "writes-outside-tmp-defect", "rule": "EXEC-01", "expected_minimal": ["/var/lib"], "manifests": true},
    {"case": "nonroot-privileged-port-defect", "rule": "EXEC-02", "expected_minimal": ["CAP_NET_BIND_SERVICE"], "manifests": false}
  ]
}
```

  `manifests` is set by running the case on the real engine. If a defect does not manifest on Podman (for example because the engine lowers `ip_unprivileged_port_start`), the case stays in the corpus with `manifests: false` and a note, and is excluded from the attribution accuracy denominator. The image of a case is `<image_prefix>/<case>:rq1`.
- Outputs stay in `-out-dir` (`rq1_results.json`, `table_rq1_detection.tex`, `raw/`). The table gets a Dockle column group and keeps label `tab:rq1_detection`.

## 5. Cross-check, agreement, statistics

`tools/crosscheck` (package main, binary `bin/crosscheck`):

```
crosscheck -study <RESULTS_DIR>/lint/empirical_study.json -dockle dockle -engine podman -platform linux/amd64 -out-dir <RESULTS_DIR>/crosscheck [-images a,b] [-limit N] [-timeout 10m] [-analyze-only]
```

- For each COMPLETED image: `save --format docker-archive` into a temporary file, check that the archive's config digest equals the study record's `config_digest` (mismatch is a recorded error, not a result), run Dockle, delete the archive, record seconds for export and for Dockle separately.
- Mapping, rule ID to Dockle code (whether an entry is a finding follows the counting rule of section 10, amendment A2): SPEC-01 to CIS-DI-0001, CIS-4.6 to CIS-DI-0006, FS-04 to CIS-DI-0008, SPEC-07 to CIS-DI-0009, SPEC-03 and FS-06 and FS-12 to CIS-DI-0010, FS-08 to DKL-LI-0001, SPEC-09 to CIS-DI-0007, SPEC-10 to DKL-DI-0001, SPEC-11 to DKL-DI-0003, SPEC-12 to DKL-DI-0002, SPEC-13 to DKL-DI-0006, FS-10 to DKL-LI-0002, FS-11 to DKL-LI-0003, FS-01 to DKL-DI-0004 and DKL-DI-0005. Dockle CIS-DI-0002 and CIS-DI-0005 inspect the scanner host and are excluded and listed as such. Dockle codes without a ConUnit counterpart are listed.
- A 2x2 per mapped check over images where ConUnit is verified and Dockle ran: both, only ConUnit, only Dockle, neither. ConUnit UNVERIFIED and Dockle errors are counted separately. Raw percent agreement is reported. No kappa.
- Outputs: `crosscheck.json` (tool versions, mapping, per image and check results, 2x2, timings), `discordances.csv` (columns `image,check,dockle_code,conunit_outcome,dockle_finding,conunit_evidence,dockle_alert,intended_difference,resolution,resolved_by`), `table_crosscheck.tex` (label `tab:crosscheck`), `macros_crosscheck.tex`.
- Macros, per mapped check with key `<K>`: `\ConUnitXchkBoth<K>`, `\ConUnitXchkOnlyConUnit<K>`, `\ConUnitXchkOnlyDockle<K>`, `\ConUnitXchkNeither<K>`, `\ConUnitXchkUnverified<K>`, `\ConUnitXchkDockleError<K>`, `\ConUnitXchkAgree<K>` (percent, one decimal). Totals: `\ConUnitXchkImages`, `\ConUnitXchkDiscordant`, `\ConUnitXchkResolved`, `\ConUnitXchkDockleVersion`.
- `tools/adjudication export` gains `-crosscheck <crosscheck.json>`: every discordant image and check becomes a row of the same two-rater sheet with item type `crosscheck`. `score` reports them separately.
- `tools/agreement`: run-to-run agreement per check is raw percent agreement over images verified in both runs plus the list and count of flipped images. Cohen's kappa leaves the run-to-run output (it stays in `tools/adjudication` for the two raters). Outputs `agreement.json`, `table_agreement.tex` (label `tab:agreement`) and `macros_agreement.tex` with `\ConUnitAgrImages`, `\ConUnitAgrFlipped` and per check `\ConUnitAgrPct<K>`.
- Exporter (`tools/export_latex.go`): new flag `-pinned <fixtures/evaluation_dataset_pinned.json>`. Macros `\ConUnitNAlpineTag` and `\ConUnitNSlimTag` count completed images whose `original_tag` contains `alpine` or `slim`, and `\ConUnitNTagged` is the number of completed images with a known tag. Without the flag they read `n/a` and the exporter warns.
- `pkg/runenv/tools.go`: add `dockle` to the probed tools.
- Coverage matrix: `docs/COVERAGE_MATRIX.md` and `table_coverage.tex` (label `tab:coverage`, supplement): each check of the hardening profile and the `lint` pack against each Dockle checkpoint and each control of the Anchore CIS pack, marked overlap, ConUnit-only or Dockle-only, with sources.

## 6. Tier 3 validation, reliability, cost

`tools/attribute_exec` (binary `bin/attribute_exec`) keeps its current flags and gains:

- `-minimize` (default true): after the union resolves, remove candidates one at a time while the container still survives, and report `minimal_set`. New attribution status `RESOLVED_MINIMAL` (a minimal set of two or more, or a single one found by minimization). Existing statuses stay.
- `-truth <tier3_truth.json> -image-prefix <prefix>`: attribute the seeded images directly (no study needed), compare `minimal_set` with `expected_minimal`: `EXACT`, `SUPERSET`, `WRONG` or `NOT_MANIFESTED`. Cases with `manifests: false` are reported and excluded from the accuracy denominator.
- `-ablation`: for every image of the study whose Tier 3 results are UNVERIFIED with reason `BASELINE_FAILED` or `NOT_OBSERVABLE`, run the four treatments (read-only rootfs with the base tmpfs, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `--memory=256m`) with the same defensive flags and no baseline gate, observe at W, and count how many a single-run tool would have called FAIL (container not running at W). Output `ablation.json`.
- Outputs: `attribution.json`, `attribution.csv`, `ablation.json`, `table_attribution.tex` (label `tab:attribution`, supplement), `macros_attribution.tex`.
- Macros: `\ConUnitAttrSeededN`, `\ConUnitAttrSeededExact`, `\ConUnitAttrSeededSuperset`, `\ConUnitAttrSeededWrong`, `\ConUnitAttrRealPairs`, `\ConUnitAttrRealReproducible`, `\ConUnitAttrRealNamedSingle`, `\ConUnitAttrRealNamedMinimal`, `\ConUnitAttrRealUnionOnly`, `\ConUnitAttrRealUnresolved`, `\ConUnitAblExamined`, `\ConUnitAblMisblamed`.

`tools/reliability` (new, binary `bin/reliability`):

```
reliability -runs r1=<dir>,r2=<dir>,r3=<dir> -windows w3=<dir>,w10=<dir>,w30=<dir> -out-dir <dir>
```

Each dir holds an `empirical_study.json` of the 10-image subset. Output `reliability.json`, `table_reliability.tex` (label `tab:reliability`, supplement), `macros_reliability.tex`: `\ConUnitRelRepeats`, `\ConUnitRelImages`, `\ConUnitRelFlippedImages` (images with any verdict change across the repeats at W of 3 s), `\ConUnitRelFlippedChecks` (check and image pairs that changed), `\ConUnitRelWindowChanged` (pairs whose verdict differs between 3, 10 and 30 s), and the window values as `\ConUnitRelWindowShort`, `\ConUnitRelWindowMid`, `\ConUnitRelWindowLong`.

`tools/benchmark_rq3`: new flag `-dockle <binary>`. For each image and trial it also times the archive export and the Dockle analysis on the same host and trials, written to `rq3_telemetry.json` as `dockle_export_ms` and `dockle_run_ms` per trial and to `macros_rq3.tex` as `\ConUnitRqThreeDockleMedian` (seconds per image, export plus analysis), `\ConUnitRqThreeDockleExportMedian` and `\ConUnitRqThreeDockleRunMedian`. New macro `\ConUnitTierThreeFloor` is (1 plus the number of Tier 3 treatments of the pack) times W in seconds, derived from the pack and the window and not typed. The runner is checked to confirm that the baseline and the treatments run one after another, and the macro text states that assumption.

## 7. Infrastructure

- `eval-infra/tools.lock`: one line per tool, `name version url sha256`, for `dockle`, `hadolint`, `trivy` and `container-structure-test`, linux amd64. The installer verifies the sha256 (preferably against the release's own checksum file, fetched from a different path than the binary) and installs to `/usr/local/bin`. The installed versions go to `host/tool_versions.json` and into `run_manifest.json` under `tool_versions`. A stage that needs a tool fails early if it is missing. Trivy is only ever run with offline flags.
- Binaries built on the instance in `build_tools`: `bin/rq1` (from `./tools/rq1`), `bin/crosscheck`, `bin/attribute_exec`, `bin/reliability`, next to the existing ones.
- New stages and what each runs, from `$SRC_DIR`, through `engine_user` where an engine is needed:
  - `rq1`: `bin/rq1 -oracle fixtures/rq1/oracle.json -out-dir $RESULTS_DIR/rq1 -conunit bin/con-unit -keep-images` (outputs in `rq1/`, images kept for `attribute`).
  - `lint`: the `con-unit eval` command of section 3.
  - `crosscheck`: `bin/crosscheck -study $RESULTS_DIR/lint/empirical_study.json -dockle dockle -out-dir $RESULTS_DIR/crosscheck`.
  - `attribute`: `bin/attribute_exec -study $RESULTS_DIR/empirical_study.json -out-dir $RESULTS_DIR/attribution`, and with the seeded images present `-truth fixtures/rq1/tier3_truth.json -image-prefix localhost/conunit-rq1`.
  - `ablate`: `bin/attribute_exec -ablation -study $RESULTS_DIR/empirical_study.json -out-dir $RESULTS_DIR/attribution` (the same directory as `attribute`, amendment A1).
  - `reliability`: three evals of the 10-image dataset at W of 3 s into `reliability/r1`, `r2`, `r3`, one at 10 s into `reliability/w10`, one at 30 s into `reliability/w30`, images kept in the store between runs, then `bin/reliability` over them into `$RESULTS_DIR/reliability`.
  - `export` additionally passes `-pinned fixtures/evaluation_dataset_pinned.json`.
  - `rq3` additionally passes `-dockle dockle`.
- Run A stages: `eval,export,rq3,rq1,lint,crosscheck`. Run B stages: `eval,export,attribute,ablate,reliability`. Recipes `final-a` and `final-b` in `eval-infra/justfile` with run ids that differ by suffix `-a` and `-b`. The canary exercises every stage on 3 images, 4 RQ1 cases (`--rq1-cases`) and a 3-image reliability subset.
- The run block check requires the tool versions for every requested stage. Redaction and `just scan --identifiers` stay clean on all new outputs. `justfile`, README timing and cost, offline tests and shellcheck are updated together.

## 8. Inputs of the paper

- Placeholder files, committed under `icpc-2027-tool-demo/results/`, each printing `[pending]` for every macro of section 5 and 6 and rendering a visible pending frame for tables: `macros_crosscheck.tex`, `macros_attribution.tex`, `macros_reliability.tex`, `macros_agreement.tex`, `table_crosscheck.tex`, `table_attribution.tex`, `table_reliability.tex`, `table_agreement.tex`, `table_coverage.tex`. `main.tex` and `supplement.tex` input them. `lint_numbers.sh` keeps failing on hand-typed result numbers, and its self-test is extended.
- The justfile of the paper repository: `paper-data` copies the new generated files (`crosscheck/*`, `attribution/*`, `reliability/*`, `lint/` macros if any, `table_coverage.tex`, `macros_agreement.tex`) from both run bundles, keeps working when a file is missing, and `build` is repointed to the demo build.
- Labels: `tab:crosscheck`, `tab:attribution`, `tab:reliability`, `tab:agreement`, `tab:coverage`, `tab:rq1_detection`.
- Figures of earlier smoke runs, which the number lint of the paper lists as patterns, must not survive in the tracked files of either repository, except in those patterns.

## 9. Test requirements

- Every tool: new behaviour has table-driven unit tests with positive, negative and edge cases. `go vet`, `gofmt` and `go test ./...` stay green. Shell changes pass `just validate` and `just lint` in `eval-infra`. Paper changes pass `just build-demo`.
- The lint checks: a table-driven test per check (multi-command lines, quoting, backslash continuations, BuildKit and legacy history forms, empty and malformed history giving UNVERIFIED with `EVIDENCE_INCOMPLETE`, whiteouts, replaced entries and hard links for the file checks, fixture-like paths for FS-12); a seeded defect and a clean control per check as image fixtures; a catalog test that every new rule has oracle, evidence, limits and mapping; the rule reference currency test; pack membership, order and exclusion tests; backward-compatibility tests for the SPEC-03 parameters; a regression test over small committed history and config samples taken from real official images (Alpine, Debian and a distroless image included, stripped of host paths).
- RQ1: classifier tests for Dockle JSON (findings at every level, empty details, malformed JSON, tool error), oracle validation tests (every `source` present, every Dockle-out-of-scope property has a reason), and a test that the seeded cases and the truth file agree.
- Cross-check: tests for the mapping, the 2x2 and discordance logic, digest mismatch handling, the adjudication export rows and the agreement flip list, plus golden files for the new LaTeX outputs.
- Attribution and reliability: tests with a fake container runner for minimization, `EXACT`, `SUPERSET`, `WRONG` and `NOT_MANIFESTED`, the ablation count, and the reliability flip and window logic.

## 10. Amendments (binding, they supersede the text above)

These changes were made while the tools were built. `docs/DEVIATIONS.md` gives the reasons.

- A1. One output directory for `attribute`, the seeded truth run and `ablate`: `$RESULTS_DIR/attribution`. `attribution.json`, `attribution.csv`, `ablation.json`, `table_attribution.tex` and `macros_attribution.tex` live there, and `macros_attribution.tex` carries all `\ConUnitAttr...` and `\ConUnitAbl...` macros. There is no `ablation/` directory. Every invocation of `attribute_exec` renders the macro and table files from its own data and from the files already in the directory. A block that is not computed prints `n/a` and is kept under `carried_over` in `attribution.json`. `-truth` can be used without `-study`, and `-ablation` runs the ablation only. Exit code 3 means that an image was absent or the engine failed.
- A2. Dockle counting rule, verified in the source of Dockle v0.4.15 (commit 54368575). Levels in the JSON are INFO, WARN, FATAL, SKIP and IGNORE. An entry for a mapped code is a finding at level INFO, WARN or FATAL, and an unknown level is a finding. An entry at level SKIP is a finding only if some alert does not start with "failed to detect ", otherwise Dockle did not evaluate the property and the case is counted as NOT_EVALUATED, never as a detection and never as a miss. IGNORE and PASS are not findings. The report is parsed from the first line that is exactly `{`, because log lines go to stdout. An ERROR or FATAL log line before the report is a tool error. An assessor error is only logged and Dockle still exits 0, so no entry can hide a failed assessor. Every `DOCKLE_*` variable is removed from the environment of Dockle and it runs in an empty working directory. `dockle --version` prints `dockle version 0.4.15` and there is no version subcommand.
- A3. Not comparable and excluded. SPEC-13 against DKL-DI-0006 is not comparable, because Dockle evaluates that checkpoint only when it receives an image name, never with `--input`. It reads `n/a` in every cross-check macro, is outside the 2x2 and the agreement, and is not a row of `discordances.csv`. CIS-DI-0002 has no code path in Dockle 0.4.15 and CIS-DI-0005 reads the scanner host, so both are excluded and listed.
- A4. Additions of `tools/crosscheck`: `table_discordances.tex` (label `tab:discordances`, split into floats of 28 rows), `table_coverage.tex` (label `tab:coverage`, written by every run), the macros `\ConUnitXchkDockleNotEvaluated<K>`, `\ConUnitXchkImages` (images with a Dockle result), `\ConUnitXchkDiscordant`, `\ConUnitXchkResolved` (`n/a` unless `-adjudication` is given) and `\ConUnitXchkDockleVersion`, the flags `-adjudication` and `-keep-pulled`, and the subcommand `crosscheck coverage -md FILE -tex FILE`. The mapped checks are SPEC-01, CIS-4.6, FS-04, SPEC-07, SPEC-03, FS-06, FS-12, FS-08, SPEC-09, SPEC-10, SPEC-11, SPEC-12, SPEC-13, FS-10, FS-11 and FS-01. Exit code 3 means that outputs were written and at least one image has no Dockle result. `docs/COVERAGE_MATRIX.md` is generated and has a currency test. The alpine and slim counts search the tag part of `original_tag`.
- A5. `tools/agreement` writes `agreement.json` (schema 2), `table_agreement.tex` and `macros_agreement.tex` with `\ConUnitAgrImages`, `\ConUnitAgrFlipped` and `\ConUnitAgrPct<K>`. Run-to-run output has raw percent agreement and the list of flipped images and no kappa.
- A6. `tools/adjudication export -crosscheck FILE` adds one row per discordance with category `crosscheck`, whose first evidence line is `kind: only_conunit` or `kind: only_dockle`. `score` reports these rows apart, in a `crosscheck` section of `adjudication_summary.json` (schema 2). Kappa stays there for the two human raters.
- A7. `tools/reliability` and `tools/benchmark_rq3`: extra macros `\ConUnitAttrSeededNotManifested`, `\ConUnitRelPairs`, `\ConUnitRelPairsTierThree` and `\ConUnitRelFlippedChecksTierThree`. `\ConUnitRelFlippedChecks` is counted over exactly the pairs that have PASS or FAIL in every repeat. The macros `\ConUnitTierThreeFloor`, `\ConUnitRqThreeDockle...Median` and `\ConUnitRelWindow...` are plain numbers in seconds without a unit. The floor counts every Tier 3 check that starts a container for W, including EXEC-03. The prefix `\ConUnitRqThree...` of the Dockle macros differs in case from the existing `\ConUnitRQThree...` macros. A seeded case has the extra verdict INCOMPLETE (image absent or engine error), which is in no count and makes the run exit 3. A case with `manifests: true` whose run is not reproduced scores WRONG.
- A8. `tools/rq1`: five tools (Hadolint, Trivy, container-structure-test, Dockle, ConUnit). `fixtures/rq1/oracle.json` has schema version 2 with the published catalogs and a `source` per entry. A new class NOT_EVALUATED has the symbol `n/e`. `fixtures/rq1/tier3_truth.json` requires `manifests` and has an optional `note` that is required when `manifests` is false. The config digest of the archive is in `raw/<case>/run.json`. The flags `-engine` and `-require-all` exist, and `-conunit` is an absolute path in the pipeline. Trivy check ids use the catalog form `DS-0002`, container-structure-test results are named `Command Test: <name>`, and a test that could not start is an error and never a detection.
- A9. `eval-infra`: the flags `--rq1-cases N` (0 means all, the canary default is 4) and `--tools-lock-sha256`, a canary that runs all nine stages by default, the manifest fields `tool_versions.installed`, `tool_versions.lock_sha256_shipped`, `dataset.reliability` and `execution.rq1_cases`, `status.json` fields `stages.<name>.outputs` and `external_tools`, and the files `host/tool_versions.json`, `host/tools.lock`, `reliability/run_exit_codes.tsv` and `attribution/seeded_build/`. Stage exit codes: 127 a tool or binary is missing and nothing ran, 66 an input or main output is missing, 3 incomplete. Run B builds the seeded images with `bin/rq1` when they are absent. The final recipes use a 240 minute watchdog and the run id base `FINAL_RUN_BASE` (default `eval-v1`) with the suffixes `-a` and `-b`.
- A10. External tools are pinned to the versions of the RQ1 oracle sources, the Nix development shell and `eval-infra/tools.lock`: Dockle 0.4.15, Hadolint 2.14.0, Trivy 0.76.1 and container-structure-test 1.22.1. The checksums of `tools.lock` equal the checksum files that the releases publish.
- A11. No check states a CIS control number (docs/DEVIATIONS.md, DEV-15): every check is a custom ConUnit check. FS-04, FS-05 and FS-09 are UNVERIFIED with EVIDENCE_INCOMPLETE when an unresolved hard link could hide a finding. FS-01 counts a path only when it holds content. CIS-4.6 reads the healthcheck from the Podman inspect layout.
- A12. Material of earlier smoke runs is not kept in this repository.
- A13. New output file names are registered in the ownership table of `tools/verify_eval_integrity.sh`: `agreement` (with `macros_agreement.tex`), `crosscheck`, `attribute_exec` and `reliability`.
