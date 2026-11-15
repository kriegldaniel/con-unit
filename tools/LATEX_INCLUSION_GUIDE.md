# LaTeX Inclusion Guide for ConUnit Artifacts

Every result number in the paper is a LaTeX macro or a generated table. All of them come from one `empirical_study.json`, so no result is typed by hand. This guide describes the generated files, the macro naming, the table labels the paper text relies on, and how to regenerate and verify everything.

## 1. Generating the files

```sh
go run ./tools/export_latex.go -paper-dir ../submission/icpc-2027-tool-demo \
    -audit fixtures/evaluation_dataset_audit.json results/empirical_study.json
```

Flags (before or after the study path):

- `-out DIR`: directory for `study_stats.json` and, without `-paper-dir`, for the `.tex` files. Default: the directory of the study JSON.
- `-paper-dir DIR`: write every generated `.tex` file to `DIR/results/`. The paper includes them as `results/<file>`.
- `-audit FILE`: `fixtures/evaluation_dataset_audit.json`, the source of the candidate and pinned counts and the sampling frame. Without it those macros read `n/a` and the exporter warns.
- `-pinned FILE`: `fixtures/evaluation_dataset_pinned.json`, the source of the image tags. Without it `\ConUnitNAlpineTag`, `\ConUnitNSlimTag` and `\ConUnitNTagged` read `n/a` and the exporter warns.
- `-headline FILE` and `-archetypes FILE`: default to `fixtures/headline_checks.json` and `fixtures/archetypes.json`, relative to the working directory. Run the command from the repository root.
- `-check`: write nothing. Verify that the files on disk equal what the study JSON produces byte for byte. Use it before every paper build.
- `-list-outputs`: print the names of all generated files.

The input is the `spec.Study` envelope. The legacy array format still decodes for old artifacts; its run metadata is then unknown and the environment macros read `unknown`.

Exit status: 0 on success, 1 on a failure, 2 on a usage error, 3 when the study has no COMPLETED image (the files are still written so the attrition can be inspected).

## 2. Generated files

Written by `tools/export_latex.go` (no other tool writes these names):

- `macros_study.tex`: all macros, see section 4.
- `table_rq2_prevalence.tex`: headline checks only, label `tab:rq2_prevalence`. Single-column table, resized to the column width, about eight rows. Artifact table in the supplement; the paper body shows the same numbers as `fig_rq2_prevalence.tex`.
- `table_rq2_exploratory.tex`: every other check except excluded ones, label `tab:rq2_exploratory`. Artifact table (`table*`). Includes the fixture-only column.
- `table_attrition.tex`: label `tab:attrition`. The flow from candidates to analyzed images with every non-completed status that occurred. Single-column, resized. Supplement table; the body states the flow with the `\ConUnitN...` macros.
- `table_strata.tex`: headline checks by archetype and base family, label `tab:strata`. Every cell is failures over verified in the stratum, with the stratum size in its own column. Artifact table (`table*`).
- `table_rq3_phases.tex`: label `tab:rq3_phases`. Four images at evenly spaced duration ranks plus median and Q1 to Q3 over all completed images. Single-column, resized. Supplement table unless the page budget allows it in the body. The caption states that Tier 3 is bounded below by the probe window and is not a performance result.
- `table_unverified.tex`: label `tab:unverified`. UNVERIFIED results by check and reason, including excluded checks. Artifact table.
- `fig_rq2_prevalence.tex`: the complete single-column figure float (caption, label `fig:rq2_prevalence`), drawn with plain TikZ at 88 mm, unscaled. Left panel: one row per headline check with the prevalence point and its Wilson 95 percent interval and the fail over verified counts. Right panel: verified versus UNVERIFIED share per check, split by reason, with hatch patterns so it reads in grayscale. A study without completed images produces a dashed pending frame with the same label. Body figure; it replaces the prevalence table in the body.
- `fig_rq3_phase_breakdown.tex`: stacked bars of one pass for up to eight images at evenly spaced duration ranks.
- `fig_rq3_memory_scaling.tex`: ConUnit live heap against scanned size. Memory is the ConUnit process only.
- `preview_paper.tex`: standalone document that includes everything, for a quick visual check. Compile it from the directory that holds the generated files.
- `study_stats.json`: every computed statistic in one JSON file (counts, intervals, per-image values, strata, flow, warnings). Not LaTeX; written to `-out`.

Written by other tools and included when present:

- `table_rq3_trials.tex`, `macros_rq3.tex` by `tools/benchmark_rq3`.
- `table_rq1_detection.tex` by the RQ1 runner: a compact shaded symbol matrix (properties as rows, tools as column groups, defect and clean-control columns) that needs the `colortbl` package, loaded with `\usepackage[table]{xcolor}`.
- `agreement.json`, `table_agreement.tex` (`tab:agreement`) and `macros_agreement.tex` by `tools/agreement`.
- `crosscheck.json`, `discordances.csv`, `table_crosscheck.tex` (`tab:crosscheck`), `table_discordances.tex` (`tab:discordances`), `macros_crosscheck.tex` and `table_coverage.tex` (`tab:coverage`) by `tools/crosscheck`.
- `attribution.json`, `attribution.csv`, `ablation.json`, `table_attribution.tex` (`tab:attribution`) and `macros_attribution.tex` by `tools/attribute_exec`, all in one directory.
- `reliability.json`, `table_reliability.tex` (`tab:reliability`) and `macros_reliability.tex` by `tools/reliability`.

The labels `tab:attrition`, `tab:rq2_prevalence`, `tab:rq2_exploratory`, `tab:strata`, `tab:rq3_phases`, `tab:rq1_detection` and `fig:rq2_prevalence` are part of the contract with the paper text. The old labels `tab:rq2_defect_prevalence` and `tab:rq3_performance` no longer exist. The evaluation tools of version 2 add the labels `tab:crosscheck`, `tab:discordances`, `tab:coverage`, `tab:agreement`, `tab:attribution` and `tab:reliability`. Their tables may use only `booktabs`, `xcolor` with the `table` option and the TikZ libraries that the paper loads.

The paper needs these packages: `booktabs`, `graphicx`, `xcolor` with the `table` option, `tikz` with `\usetikzlibrary{patterns}`. Only the optional RQ3 figures (`fig_rq3_*`) need `pgfplots` (with `\pgfplotsset{compat=1.18}`). Include the macros once, before the text that uses them:

```latex
\input{results/macros_study.tex}
\input{results/table_rq2_prevalence.tex}
```

## 3. What the statistics mean

- Only images with status COMPLETED enter statistics. Every other attempted image is in the attrition flow with its status.
- For a check, verified means PASS or FAIL. Prevalence is FAIL divided by verified, with a Wilson 95 percent interval. UNVERIFIED results enter neither numerator nor denominator and are reported by reason.
- A check with no verified image has no prevalence: its cells read `n/a`, never zero.
- FS-06 and FS-07: only findings outside fixture-like paths make a result FAIL. Findings under `testdata`, `test`, `tests`, `fixtures`, `fixture`, `examples` or `example`, and the Debian snakeoil keys, are fixture candidates. If only those exist the result is PASS and the image counts in the fixture-only column.
- There is no per-image pass rate and no fully compliant count. Per image the exporter reports confirmed failures among verified checks together with the number of verified checks; the distribution is summarized with median, quartiles, mean and the sample standard deviation (divisor n-1).
- Checks listed under `excluded` in `fixtures/headline_checks.json` (SUP-02) appear in no prevalence table, figure or prevalence macro. Rules missing from that file are treated as exploratory and the exporter warns.
- The standard column comes from the rule metadata of the results. A rule without metadata prints `unmapped`.

## 4. Macros

All macros are defined with `\newcommand` in `macros_study.tex` and their names contain letters only.

Per check, with the rule ID key defined as: remove hyphens and dots, spell out every digit. SPEC-01 becomes `SPECZeroOne`, FS-04 becomes `FSZeroFour`, CIS-4.6 becomes `CISFourSix`, EXEC-02 becomes `EXECZeroTwo`.

- `\ConUnitPrev<key>`, `\ConUnitPrevLo<key>`, `\ConUnitPrevHi<key>`: prevalence and Wilson bounds as a percentage with one decimal, for example `12.3\%`. `n/a` without verified images. Not defined for excluded checks.
- `\ConUnitFail<key>`, `\ConUnitPass<key>`, `\ConUnitVerified<key>`, `\ConUnitUnverified<key>`: counts. Defined for every check, including excluded ones.
- `\ConUnitFixtureOnly<key>`: images with fixture-only candidates. Not defined for excluded checks.

Flow and attrition:

- `\ConUnitNCandidates`, `\ConUnitNPinned`, `\ConUnitNPreExcluded`, `\ConUnitFrameCommit`, `\ConUnitFrameDate` from the dataset audit.
- `\ConUnitNAttempted`, `\ConUnitNCompleted`, `\ConUnitNAttrition`.
- `\ConUnitAttritionTimeout`, `Unavailable`, `RateLimited`, `IndexLimit`, `ExecutionError`, `Excluded` (prefix `\ConUnitAttrition`): counts per status, zero when none.
- `\ConUnitInfraAttrition` and `\ConUnitInfraAttritionPct`: records in the infrastructure statuses (rate limited, execution error, unavailable, timeout) and their share of the attempted images. The analysis plan reruns above 5 percent.

Environment, read from the `run` block of the study and escaped for LaTeX (CPU model strings contain characters such as `@`, parentheses and `&`). Unknown values read `unknown`:

- `\ConUnitEnvInstanceType`, `\ConUnitEnvEngine`, `\ConUnitEnvKernel`, `\ConUnitEnvVirt`, `\ConUnitEnvAMI`, `\ConUnitEnvCommit` (12 characters, `+dirty` appended for a tainted run), `\ConUnitEnvOS`, `\ConUnitEnvCPU`, `\ConUnitEnvDate`.
- Additional: `CommitFull`, `Region`, `VCPUs`, `MemoryGiB`, `Rootless`, `StorageDriver`, `OCIRuntime`, `CgroupVersion`, `ExecutionMode`, `Platform`, `ImageSource`, `RegistryRemap`, `Pack`, `Version`, `DatasetSHA`, `Tainted`, `ProbeWindow` (all with the `\ConUnitEnv` prefix).

Per-image distribution, with suffix `Headline` (headline checks) or `All` (headline and exploratory checks):

- `\ConUnitImgFailMean<suffix>`, `SD`, `Median`, `QOne`, `QThree`, `Min`, `Max`: confirmed failures among verified checks per image.
- `\ConUnitImgVerifiedMedian<suffix>`, `Min`, `Max`: verified checks per image.
- `\ConUnitImgNoFail<suffix>`: images with verified checks and no confirmed failure. `\ConUnitImgNoVerified<suffix>`: images with no verified check.
- `\ConUnitNHeadlineChecks`, `\ConUnitNExploratoryChecks`, `\ConUnitBatchPeakRSS` (the ConUnit process memory ceiling over the batch, megabytes, not per image).

Image tags, from `-pinned`: `\ConUnitNAlpineTag` and `\ConUnitNSlimTag` count the completed images whose tag (the part of `original_tag` after the colon) contains `alpine` or `slim`, and `\ConUnitNTagged` counts the completed images with a known tag.

Written by the evaluation tools of version 2, each into its own file (see `docs/INTERFACE_V2.md`, section 10):

- Agreement, `macros_agreement.tex`: `\ConUnitAgrImages`, `\ConUnitAgrFlipped`, `\ConUnitAgrPct<key>`.
- Cross-check, `macros_crosscheck.tex`. Per mapped check with its rule key: `\ConUnitXchk` followed by `Both`, `OnlyConUnit`, `OnlyDockle`, `Neither`, `Unverified`, `DockleError`, `DockleNotEvaluated` or `Agree` and then the key. Totals: `\ConUnitXchkImages`, `\ConUnitXchkDiscordant`, `\ConUnitXchkResolved`, `\ConUnitXchkDockleVersion`. SPEC-13 reads `n/a` throughout. The mapped checks are SPEC-01, CIS-4.6, FS-04, SPEC-07, SPEC-03, FS-06, FS-12, FS-08, SPEC-09, SPEC-10, SPEC-11, SPEC-12, SPEC-13, FS-10, FS-11 and FS-01.
- Tier 3: `macros_attribution.tex` holds every `\ConUnitAttr...` and `\ConUnitAbl...` macro, and `macros_reliability.tex` holds the `\ConUnitRel...` macros. The names are listed in the interface contract.
- Cost, in `macros_rq3.tex`: `\ConUnitTierThreeFloor` and the `\ConUnitRqThreeDockle...Median` macros. They are plain numbers in seconds without a unit.

If the paper uses a macro for a check that the study does not contain, LaTeX stops with an undefined control sequence. That is intended: the missing result is visible.

## 5. Verification

Three layers, from fast to complete:

1. `go run ./tools/export_latex.go -check ...` with the same arguments as the generation command. Fails when any generated file is missing or differs.
2. `tools/verify_eval_integrity.sh [results-dir]`. Reconciles the dataset lists, pinned JSON and audit, checks the envelope, one record per attempted image, no duplicate test IDs, the macros against an independent `jq` recount of the JSON, non-empty generated files and that no two tools write the same file name. `INTEGRITY_STRICT=1` turns warnings into failures; use it for the final run. Set `PAPER_DIR` when the generated files live in the paper directory.
3. `go test ./tools/...`. The exporter tests use synthetic studies and golden files in `tools/testdata/export_latex/golden`. Regenerate them with `go test ./tools -run Golden -update` after an intended change and review the diff. With a TeX installation, `TestGeneratedLatexCompiles` builds `preview_paper.tex`; set `PDFLATEX` to point at a `pdflatex` binary.

## 6. Related tools

- `tools/pin_dataset`: pins the candidate list to index digests and writes `fixtures/evaluation_dataset_audit.json` (sampling frame via `-frame-commit` and `-frame-date`, inclusion rule, exclusion log, list sha256, counts). It issues one manifest request per candidate, about 108 anonymous Docker Hub pulls, so run it at most once per six hours and keep `-delay` above zero. It stops on HTTP 429 and leaves all outputs untouched. `-audit-only` rebuilds the audit offline. It derives the top-10 pinned list from the main run, so containment holds by construction.
- `tools/check_mirror.sh <pinned-list>`: HEAD-checks every pinned digest on the ECR Public mirror, spaced by `MIRROR_DELAY` (default 1.1 seconds), and writes `mirror_check.json` to `OUT_DIR`. Exits non-zero on any miss.
- `go run ./tools/adjudication export` and `score`: the two-rater validity study. `export` writes `adjudication_template.csv`; `score` reads the filled file and writes `adjudication_summary.json` with Cohen's kappa and precision per check with Wilson intervals. `export -crosscheck FILE` adds one row per Dockle discordance, and `score` reports those rows apart, in a `crosscheck` section (schema 2).
- `go run ./tools/agreement -a RUN_A/empirical_study.json -b RUN_B/empirical_study.json`: per check raw percent agreement and the list of flipped images between two runs, with no kappa, because two runs of one tool are not two raters. Written to `agreement.json` (schema 2), `table_agreement.tex` and `macros_agreement.tex`.
- `go run ./tools/crosscheck -study results/lint/empirical_study.json -dockle dockle -out-dir results/crosscheck [-adjudication FILE]`: runs Dockle on the docker-archive export of each completed image and compares it with the `lint` study. Exit 0 is ok, 1 a failure, 2 a usage error, 3 outputs written with at least one image without a Dockle result. `crosscheck coverage -md FILE -tex FILE` rebuilds the coverage matrix offline.
- `go run ./tools/attribute_exec`: attributes Tier 3 failures by controlled variants with minimization (`-study`), scores the seeded cases (`-truth FILE -image-prefix PREFIX`) and runs the ablation (`-ablation -study`). All three write into one `-out-dir`.
- `go run ./tools/reliability -runs r1=DIR,r2=DIR,r3=DIR -windows w3=DIR,w10=DIR,w30=DIR -out-dir DIR`: flipped verdicts across repeats and window sensitivity on the 10-image subset.
- `go run ./tools/label_base_family -apply`: derives the base families of the pinned images from their os-release file and writes `fixtures/base_family_evidence.json`. `-from-evidence FILE` derives them again without a registry and `-dry-run` reads manifests only. It issues about two manifest requests per image, so keep `-delay` above zero. It stops on HTTP 429 and leaves all outputs untouched.
- `go run ./tools/preview -dir results`: terminal overview and `preview.html` from an existing study, using the same statistics.
