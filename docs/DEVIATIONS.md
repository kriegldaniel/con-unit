# Deviations log

This file records every change to the evaluation design, the tool or the dataset that was made after version 1 of `docs/ANALYSIS_PLAN.md` and before the tag `eval-v1`, and every change after the tag. Each entry says what changed, why, what it affects and what is still open. Entries are in order of decision. Nothing here is a result.

## DEV-01: eight static checks and the `lint` pack

- Date: 2026-11-15, before any data.
- Change: an external review of 2026-11-15 lists "no new rule packs or checks" as out of scope. At the request of the authors, ConUnit gets the pack `lint` (`PACK-IMAGE-LINT`) and eight new static checks: SPEC-09, SPEC-10, SPEC-11, SPEC-12, SPEC-13 (Tier 1) and FS-10, FS-11, FS-12 (Tier 2). Nothing else of that kind is added. The hard-link repair of DEV-03 fixes an existing check, and the extra RQ1 properties extend the corpus, not the tool.
- Reason: every image-level Dockle checkpoint should have a ConUnit check, so that static coverage is at least that of Dockle and is shown by the coverage matrix and the cross-check, not asserted.
- Effect: the 17-check hardening profile is unchanged. The `lint` study adds about 10 minutes to run A. All new checks start exploratory (analysis plan, section 4). They are reimplemented from the documented behaviour of Dockle, not copied.
- Open: the intended differences from Dockle (command tokenizing, user resolution) will appear as discordances and are listed per check in the rule catalog.

## DEV-02: CIS Docker Benchmark 1.8.0 and own control descriptors

- Date: 2026-11-15, before any data.
- Change: the tool mapped to CIS Docker Benchmark 1.6.0. It now names version 1.8.0. Version 1.8.0 starts section 5 with a swarm mode control, so the controls of section 5 that the tool uses move up by one: capabilities 5.3 to 5.4, privileged ports 5.7 to 5.8, memory 5.10 to 5.11, read-only root filesystem 5.12 to 5.13, no-new-privileges 5.25 to 5.26. The PID limit that the memory check mentions moves from 5.28 to 5.29. The section 4 controls used (4.1, 4.3, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10, 4.12) keep their numbers.
- SUP-02 maps to 4.12. That control exists in version 1.6.0 as well (checked in the tagged test scripts of docker-bench-security v1.6.0), so the old number was right and does not change.
- Control titles in the tool are short ConUnit descriptors in our own words. They are no longer the verbatim titles of the benchmark, because CIS asks for guidance from CIS Legal before its text is quoted. A test rejects a title that starts with "Ensure". Legacy exclusion handles keep their 1.6.0 numbers so that existing exclusion lists keep working, and `docs/RULES.md` says so.
- Verification basis. The official PDF was not read for this change: its download requires a registration with CIS, and none of the numbers was taken from a copy of the PDF hosted outside CIS (CIS forbids such hosting). The numbers were checked against two public sources instead.
  - The audit item lists that Tenable publishes for CIS Docker v1.8.0 (Authority: CIS), levels L1 and L2. They contain 4.1, 4.3, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10, 4.12, 5.4, 5.8, 5.11, 5.13, 5.26 and 5.29 with titles that match the 1.6.0 titles of the same controls (4.7 is "in Dockerfiles" instead of "in the Dockerfile").
  - The tagged test scripts of docker-bench-security v1.6.0, which implement version 1.6.0: 4.12 exists, 5.3 is capabilities, 5.7 is privileged ports, and section 5 has no swarm mode control.
- Not verified: the content of the recommendations (rationale, audit procedure) was not compared between 1.6.0 and 1.8.0, and the 27 recommendations that 1.8.0 updated were not compared one by one. The exact or approximate label of each mapping is carried over from the previous version.
- Open for the authors: confirm the numbers and the mapping labels of 4.1, 4.3, 4.6, 4.7, 4.8, 4.9, 4.10, 4.12, 5.4, 5.8, 5.11, 5.13, 5.26 and 5.29 against the official PDF, which CIS provides after registration, before the freeze. Any number that cannot be confirmed is to be emptied and its mapping changed to custom.
- Update: DEV-15 applies this fallback. The numbers are removed from the tool.

## DEV-03: hard links are resolved through their same-layer target

- Date: 2026-11-15, before any data.
- Change: the filesystem index ignored hard-link entries for the SUID, world-writable, ownership and key-file checks. A hard link is another directory entry of the same inode, so it now takes the mode, owner and key-scan result of the file it names in the same layer. A link whose target is not a file of the same layer, or that forms a cycle, is unresolved and is never guessed.
- Effect: FS-04, FS-05 and FS-09 return UNVERIFIED with EVIDENCE_INCOMPLETE when they found nothing and an unresolved link could hide a finding. A finding still gives FAIL. FS-09 only counts unresolved links in `/bin`, `/usr/bin`, `/sbin` and `/usr/sbin`. The OCI image specification does not forbid a link to a file of a lower layer but warns that such a layer may fail to extract, and the mode and owner of a lower layer entry are not kept, so such links are reported as unresolved.
- Open: the number of images with unresolved links in the final run is reported as part of the UNVERIFIED breakdown.

## DEV-04: base families come from the os-release file

- Date: 2026-11-15, before any data.
- Change: the 26 pinned images whose base family was `unknown` are labeled from the `os-release` file of the image itself. `tools/label_base_family` reads the layers of the linux/amd64 image from its digest, applies whiteouts and links, and reads `/etc/os-release`, with `/usr/lib/os-release` as the fallback of os-release(5). The raw text, the marker files, the config digest and the deciding rule are stored in `fixtures/base_family_evidence.json`, and the derived family is written to `fixtures/archetypes.json` for the repositories that were `unknown`. Labels of other repositories are not changed. An image without any release file is labeled from release marker files, is `scratch-or-distroless` when it has no shell, and stays `unknown` otherwise. Nothing is guessed from the repository name.
- Reason: the sentence of the external review on alpine and slim variants and the stratification of the results by base family both need labels that can be checked.
- Open: the evidence file can be re-derived without a registry (`-from-evidence`) if a rule changes.

## DEV-05: contract amendments while the tools were built

These changes to `docs/INTERFACE_V2.md` were decided while the tools were built. The file itself carries them.

- One output directory for the stages `attribute`, `ablate` and the seeded truth run: `$RESULTS_DIR/attribution`. `macros_attribution.tex` carries all `\ConUnitAttr*` and `\ConUnitAbl*` macros, so no file name clash arises in the data copy.
- Dockle counting rule: the sentence "a Dockle entry at any level is a finding" is replaced by the rule of analysis plan section 7. The levels are INFO, WARN, FATAL, SKIP and IGNORE. SKIP is a finding only if some alert does not start with "failed to detect". The report is parsed from the first line that is exactly `{`, every `DOCKLE_*` variable is removed and Dockle runs in an empty working directory. These facts were read from the source of the pinned Dockle.
- SPEC-13 against DKL-DI-0006 is not comparable: Dockle evaluates that checkpoint only when it receives an image name, never with `--input`. CIS-DI-0002 has no code path in the pinned Dockle and CIS-DI-0005 reads the scanner host. Both are excluded.
- `crosscheck` also writes `table_discordances.tex` (label `tab:discordances`) for the list of resolved discordances in the supplement.
- `reliability` also reports the denominator of the stability rule (`\ConUnitRelPairs`).
- The macros `\ConUnitTierThreeFloor`, `\ConUnitRqThreeDockle*Median` and `\ConUnitRelWindow*` are plain numbers in seconds. The paper adds the unit.
- The external tools are pinned to the versions of the Nix development shell and of the RQ1 oracle sources: Dockle 0.4.15, Hadolint 2.14.0, Trivy 0.76.1 and container-structure-test 1.22.1. `tools.lock` carries the same versions, so the local smoke run and the AWS run agree with the oracle.
- Material of earlier smoke runs is not kept in this repository. A grep audit checks that none of their figures survives in the tracked files.

## DEV-06: analysis plan version 2

- Date: 2026-11-15, before any data.
- Change: `docs/ANALYSIS_PLAN.md` is rewritten as version 2. New or changed: the convenience-sample language with generated tag counts, the Tier 3 decision rule with its thresholds, the Dockle protocol and counting rule, the seeded validation, run-to-run agreement as raw percent agreement with the list of flipped images and without kappa, the window sensitivity, the origin of the base family labels, the Dockle timing phases of the benchmark, the cross-check rows of the adjudication, and the rule that the pilot is non-evidentiary.
- Open for the authors: the thresholds of the Tier 3 decision rule (every manifesting seeded case exact, at least half of the reproducible real FAILs resolved, at most 10 percent of verdicts flipping) are a proposal and are fixed before any data. They can be changed until the freeze.

## DEV-07: the image healthcheck is read from the Podman inspect layout

- Date: 2026-11-15, found in the first real RQ1 run, before any data of the final run.
- Change: on Podman, CIS-4.6 reported FAIL for images that define a HEALTHCHECK. The check reads `Config.Healthcheck`, which is where Docker reports it. Podman keeps the OCI config as it is, without that key, and reports the healthcheck in a top-level `Healthcheck` key of the inspect document. The inspect parser now reads that key and copies it into `Config.Healthcheck` when the config has none, so the OCI config stays authoritative.
- Effect: any earlier study on a Podman engine reported a false FAIL of CIS-4.6 for images with a HEALTHCHECK. The final run uses the fixed parser. In the RQ1 corpus the case `no-healthcheck-clean` was a false positive of ConUnit because of this and no longer is.
- Found by: the first run of the benchmark with real tools. Checked against Podman 5.8.1 with the real command line.

## DEV-08: the package cache check counts a path only when it holds content

- Date: 2026-11-15, before any data.
- Change: FS-01 failed whenever a listed path existed, even as an empty directory. Base images ship such directories: the pinned Alpine image has an empty `/var/cache/apk`, the pinned Debian image has empty `/var/cache/apt` and `/var/lib/apt/lists`. FS-01 therefore failed every Alpine and Debian image, including the two clean controls of the RQ1 corpus (`package-cache-clean`, `apt-lists-clean`), and the prevalence of the check would have measured the base image and not the build. A path now holds content when it is a file or a link, or a directory with at least one file or link below it at any depth.
- Effect: FS-01 is in the hygiene, NIST and lint packs and is not part of the 17-check hardening profile. The lint pack feeds the Dockle cross-check, where FS-01 is mapped to DKL-DI-0004 and DKL-DI-0005. The RQ1 result of ConUnit for the two controls changes from false positive to true negative. The corpus and the oracle were not changed. The measurement that exposed the problem is kept here.
- Follow-up: the zero-byte file rule that this entry left open was found to be wrong by the local smoke run and is changed in DEV-13.

## DEV-09: attribution reruns the treatment that failed

- Date: 2026-11-15, before any data.
- Change: `attribute_exec` mounted `/tmp` with `noexec`, which the EXEC-01 treatment of the engine does not, and it also offered `/tmp` as a candidate mount although the treatment mounts it. Attribution therefore reran a different treatment than the one that had failed. Both are fixed, and a test pins the flags of all four treatments against `pkg/engine`.
- Found by: the work on the Tier 3 tools.

## DEV-10: the RQ1 oracle and parsers were corrected after the first run with real tools

- Date: 2026-11-15, before any data.
- Change: `tools/rq1` had only been run against fixtures. With real tools, Trivy reports check ids in the catalog form `DS-0002` and not `DS002`, so every Trivy detection id was a miss. container-structure-test names its results `Command Test: <name>`, so no name ever matched, and a test that could not start also has a failed state and is now an error and never a detection. Dockle needed the level rules of DEV-05. The scopes of the oracle now come from the published catalogs of the pinned versions with a source per entry (oracle schema 2).
- Effect: the old oracle could not have produced a valid comparison. The numbers of the first complete local run (39 cases, five tools, Podman 5.8.1) are a pipeline check and not a result.

## DEV-11: choices in the lint checks that differ from the wording of the contract

- Date: 2026-11-15, before any data. Each choice is stated in the `Limits` of the check.
- SPEC-09 reads `apt-get` and `apt` as one package manager, because they share one package index. A later `install` of either completes an `update` of either. `dist-upgrade` and `full-upgrade` do not count as an upgrade, as in Dockle.
- SPEC-13 is UNVERIFIED for an image tarball, because the runner records no requested reference for a local archive. On the digest-pinned dataset it passes.
- FS-10 reports two different names that share an ID, where Dockle reports any repeated ID. FS-11 reports a directory through any path component, where Dockle reports it only through a file that is a direct child, and skips `node_modules` and `vendor` for directories only. FS-10, FS-11 and FS-12 are UNVERIFIED for an index without entries or without account data.
- Small hunks outside the files named for the lint work: `ResolvePack` and the requested reference in `pkg/runner`, a set of directory entries and the capture of `/etc/group` in `pkg/oci`, `Volumes` in the engine inspect type, and the SPEC-03 accepted-keys parameter. The behavior of the other packs is unchanged.

## DEV-12: page budget of the paper

- Date: 2026-11-15, before any data.
- Change: the new content adds about 1280 words to a body that had room for about 150. The body ends on page 4 and the references start on page 5 only with the RQ1 matrix and the Dockle cross-check table in the supplement, each with a pointer sentence in the body. The plan allows this. The probe-flow figure stays in the body, and a switch moves it to the supplement if the real results are larger. `just build-demo` now fails when the page budget is violated.
- The paper cites the CIS Docker Benchmark and says that the profile is informed by it. After DEV-15 it says that the profile is informed by topics of the benchmark and that its checks state no control numbers.

## DEV-13: zero-byte files below a listed directory do not make it a package cache

- Date: 2026-11-15, found by the local smoke run (Gate 2), before any data of the final run.
- Change: DEV-08 made FS-01 count a directory only when a file or link lies below it, and left zero-byte files counting as content. The smoke run showed that this misjudges the clean control `apt-lists-clean` of the RQ1 corpus. After `apt-get update`, `apt-get install` and `rm -rf /var/lib/apt/lists/*`, apt leaves an empty lock file at `/var/cache/apt/archives/lock`, and that was the only entry below `/var/cache/apt` in the control. The pinned Ubuntu image of the smoke subset also holds only zero-byte files below `/var/cache/apt`. The filesystem index now records regular files of zero bytes, and a listed directory holds content only when an entry other than a directory or an empty regular file lies below it. A listed path that is itself an empty file still counts (an empty `.env` is still a `.env`), and so does every link, hard links included.
- Effect: on the 39 RQ1 cases the result of ConUnit changes from TP 19, FP 1, TN 18, UNVERIFIED 1 to TP 19, FP 0, TN 19, UNVERIFIED 1. The seeded defect `apt-lists-defect` still fails FS-01 on `/var/lib/apt/lists`. The local cross-check on the smoke subset loses the FS-01 discordance on the Ubuntu image (8 discordances become 7). Images built on Ubuntu are likely to be affected in the same way, so the base image and not the build would have decided FS-01 for them. The oracle and the corpus were not changed.
- Limit: a cache that consists only of empty marker files is not seen. The catalog says so.
- Found by: the smoke run and not by a unit test. The lint pack test of DEV-01 used an empty lock file as its fixture for "apt lists present", which encoded the same mistake. It now uses a list file with content and has a second case for a lock file alone.

## DEV-14: the container state is read from stdout only

- Date: 2026-11-15, found by the first canary on a release candidate tag, the first run on the evaluation host (rootful Podman 4.9.3, Ubuntu 24.04, amd64), before any data of the final run.
- Change: `container inspect -f` was read from the combined output of the engine in two places, `pkg/engine/probe.go` (all Tier 3 checks) and `tools/attribute_exec/runner.go` (attribution). Podman 4.9 writes `Could not find mount at destination "/var/run" when parsing user volumes` to stderr when a tmpfs destination is a symlink in the image (alpine: `/var/run` points to `/run`). That line became part of the state, which was then unparseable. Both places now read stdout only and keep stderr for error messages. Podman 5.8 on the development machine does not print the warning, so the local smoke run could not show it.
- Effect: in the canary the seeded case `writes-outside-tmp-defect` ended without a verdict in the attribution (candidate mount `/var/run`). In the study itself an image whose `/tmp` is a symlink would have given PROBE_ERROR and UNVERIFIED for the read-only treatment. The regression tests make the fake engine print the real warning on stderr and fail on the earlier code.
- Pipeline note, not a tool change: the stage `rq1` passed `-require-all` together with `--rq1-cases`, so the 35 cases outside the selection were counted as not run and every canary ended incomplete. The flag is now passed for full runs only. The scanners are still required before the stage starts.
- Found by: the canary. Everything else the canary ran gave the expected results on the instance: the four tools at the pinned versions, the mirror proof, eval, export, rq3, lint, crosscheck, ablation and the reliability runs, with a verified teardown.

## DEV-15: no CIS control number is stated

- Date: 2026-11-15, before any data of the final run.
- Change: DEV-02 left the confirmation of the CIS control numbers against the official PDF to the authors. The PDF could not be consulted before the freeze, so the numbers stay unconfirmed. A number that is not confirmed is left empty and its mapping becomes custom. That concerns all fifteen checks that carried a number. They are now custom ConUnit checks of their scope. The result records, the rule reference `docs/RULES.md`, the pack descriptions and the reference texts of the results state no control number and no benchmark version. The paper cites the benchmark only as the source of topics. The legacy exclusion handles such as `CIS-4.1` and the rule ID `CIS-4.6` are unchanged: they are names that keep existing exclusion lists working and are not mappings. The test `TestNoRuleClaimsACISControlUntilItIsConfirmed` keeps the catalog in this state until a number is confirmed.
- Candidate numbers, kept here for the day they are confirmed. They are not claims. Each was found in the Tenable audit lists for version 1.8.0 (see DEV-02). SPEC-01 4.1 (exact), CIS-4.6 4.6 (exact), SPEC-09 4.7 (exact), FS-03 4.3, FS-04 4.8, SPEC-07 4.9, SPEC-03 4.10, FS-06 4.10, FS-12 4.10, SUP-02 4.12, SPEC-05 5.8, EXEC-02 5.4, EXEC-07 5.11 (the PID limit 5.29 belongs to the baseline), EXEC-01 5.13 and EXEC-04 5.26. Unless stated, the mapping was approximate.
- Effect: no result file changes shape. `rule.standard` reads ConUnit, `rule.mapping` reads custom, and `control_id`, `control_title` and `standard_version` are empty. The static and Tier 3 outcomes do not change. The comparison with Dockle and the coverage matrix do not use these numbers. The coverage matrix lists the control numbers of the Anchore pack as that pack publishes them.
- Open: confirming the numbers is still possible after the paper. Restoring them is mechanical (the catalog, the generated reference and the test).

## Open items before the freeze

- The CIS control numbers: resolved by DEV-15. The numbers are removed, so nothing has to be confirmed before the freeze.
- The thresholds of the Tier 3 decision rule (DEV-06): confirmed by the authors on 2026-11-15 and unchanged.
- The local runs prove the pipeline and not the numbers: the host is arm64 with rootless Podman.
- The seeded case `nonroot-privileged-port` does not manifest on the local engine. Decision of the authors on 2026-11-15: it stays in the corpus as a documented non-manifesting case, outside the attribution accuracy denominator. There `ip_unprivileged_port_start` is 1024 and a non-root process holds no effective capability, so `nc` cannot bind port 80 even in the baseline run (`nc: bind: Permission denied`). EXEC-02 is therefore UNVERIFIED (BASELINE_FAILED) in RQ1 and NOT_MANIFESTED in the seeded truth run, and the case is outside the attribution accuracy denominator. The premise of the case is doubtful: for a non-root process `--cap-drop=ALL` does not change whether it can bind a privileged port, only that sysctl does, and the canary of 2026-11-15 confirmed it: on the rootful Podman 4.9.3 of the evaluation instance the baseline fails as well (BASELINE_FAILED), so the case does not manifest there either. For the authors, before the freeze: keep it as a documented non-manifesting case, drop it, or replace it by a variant that needs a file capability on the binary.
- Two misses in the local RQ1 run are limits of the other tools and are part of the comparison, not errors of the harness. Hadolint reports DL3002 only for an explicit `USER root`, so the case without any USER instruction is missed. Dockle v0.4.15 matches credential file names and a short list of extensions, with `.key` and `.pem` commented out in its source, so a PEM block in `server.key` is missed.
- The new stages and the identifier scan were exercised by the canary and by a pilot of the whole pipeline on the evaluation instance (see DEV-14). The scan of a bundle of a full run reports hits in the raw scanner output of the two seeded cases `secret-in-env-defect` and `private-key-file-defect` (18 in the pilot). They are the documented AWS example key and random PEM bodies. The authors accept these hits on 2026-11-15. The final bundles are scanned the same way, and a hit anywhere else is a finding.
- The Dockle behavior stated in the `Limits` of the lint checks comes from the Dockle source. The local differential run covered 8 of the 10 subset images (postgres and redis were not pulled, to keep the anonymous registry quota) and gave 7 discordances, each with the intended difference of its check: Dockle reads ENV words of the build history for CIS-DI-0010, does not match `.pem` and `.key` files, and judges package caches from the history where FS-01 reads the filesystem (the node image holds about 3 MB of APKINDEX files in `/var/cache/apk`). The full run on the 10 images and the adjudication of the discordances are still to be done.
- The two-rater adjudication, the wording of the results text and the AI-assistance statement are for the authors.
