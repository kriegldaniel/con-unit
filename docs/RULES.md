# ConUnit rule reference

This file is generated from the code by `con-unit rules`. Do not edit it by hand: `go test ./pkg/conunit` fails when it is out of date, and `CONUNIT_UPDATE_RULES=1 go test ./pkg/conunit -run TestRulesDocumentIsCurrent` rewrites it.

## How to read a rule

Every check has a stable ID and a stable name. One image gets at most one result per rule ID in a pack run.

Outcomes:

- PASS: the oracle observed the property the check looks for.
- FAIL: the oracle observed the opposite. A FAIL states an observation, not a defect claim.
- UNVERIFIED: the evidence needed for a verdict is missing, incomplete or ambiguous. The reason says which: EVIDENCE_INCOMPLETE, FILE_MISSING, NO_TRUST_POLICY, TOOL_UNAVAILABLE, BASELINE_FAILED, NOT_OBSERVABLE, PROBE_TIMEOUT or PROBE_ERROR.

Mapping types state how closely a check corresponds to a control of a standard:

- exact: the check observes the property that the control names.
- approximate: the check observes a related property, or a stricter or narrower one. The limits of the check say how.
- custom: no control of a standard covers the check. It is a ConUnit check.

Scopes state what kind of property a check observes:

- image_content: files and packages in the image layers.
- metadata_declaration: what the image configuration, history or labels declare.
- runtime_compatibility: whether the image still starts under a restriction. It says nothing about how it is run in production.

No pack is a compliance assessment. No check states a control number of the CIS Docker Benchmark. The numbers could not be confirmed against the official document, so every check of the hardening profile is a custom ConUnit check that is informed by topics of that benchmark. docs/DEVIATIONS.md (DEV-15) says why.

## Packs

### ConUnit Container Hardening Profile (CIS-informed) (`PACK-CONUNIT-HARDENING`)

Select it with `--pack hardening` (alias `cis`).

Checks selected for their relation to topics of the CIS Docker Benchmark. No check states a control number, so every check is a custom ConUnit check with a scope. The profile is not a CIS compliance assessment: topics are only approximated, runtime topics are tested as image compatibility, and the benchmark covers many topics that this profile does not. The identifier was PACK-CIS-DOCKER before result schema version 2. The names cis, cis-docker, cisbenchmark and hardening resolve to this pack.

| Check | Name | Parameters | Legacy exclusion handles |
|:---|:---|:---|:---|
| SPEC-01 | Non-Root Execution Identity | none | CIS-4.1 |
| CIS-4.6 | Image HEALTHCHECK | none | none |
| FS-04 | SUID/SGID Privilege Escalation Vectors | none | CIS-4.8 |
| SPEC-07 | Instruction Hygiene (COPY over ADD) | none | CIS-4.9 |
| SPEC-03 | Clean Ambient Environment | disallowed keys: PASSWORD, SECRET, TOKEN, PRIVATE_KEY | CIS-4.10 |
| FS-06 | Private Key Material Scan | none | CIS-4.10 |
| FS-08 | Account Security (Empty Passwords) | none | CIS-4.10 |
| FS-05 | World-Writable File Elimination | none | CIS-4.11 |
| FS-09 | System Directory Ownership Hygiene | none | CIS-4.11 |
| FS-07 | Development and Test Harness Leakage | none | CIS-4.3 |
| SUP-02 | Cryptographic Image Provenance & Signature | uses the trust policy configured for the run | CIS-4.5 |
| EXEC-02 | Dropped Linux Capabilities Conformance | none | CIS-5.3 |
| SPEC-05 | Non-Privileged Declared Image Ports | skipped when the pack allows privileged ports | CIS-5.7 |
| SPEC-06 | Dangling Debug Port Exclusion | ports: 5005, 9229, 2375, 22, 6006 | CIS-5.7 |
| EXEC-07 | Resource Constraint Conformance | memory: 256m; the PID limit stays at the baseline value | CIS-5.10 |
| EXEC-01 | Read-Only Root Filesystem Conformance | none | CIS-5.12 |
| EXEC-04 | No-New-Privileges Kernel Contract | none | CIS-5.25 |

A pack excludes a check with its rule ID. The legacy handles are older pack-level IDs that still disable the checks listed next to them; they are exclusion handles, not mappings to a standard. A handle named after a CIS control keeps the control number it had in an older version of the benchmark, so existing exclusion lists keep working. It is a name and says nothing about the numbering of any version.

### Production Container Hygiene & Security Baseline (`PACK-PROD-HYGIENE`)

Select it with `--pack hygiene`.

A short baseline for production images that includes the signal handling and package cache checks. It is a ConUnit profile, not an implementation of a standard.

| Check | Name | Parameters | Legacy exclusion handles |
|:---|:---|:---|:---|
| SPEC-01 | Non-Root Execution Identity | none | none |
| SPEC-02 | Deterministic Entrypoint or Command | none | none |
| SPEC-03 | Clean Ambient Environment | disallowed keys: PASSWORD, SECRET, TOKEN, PRIVATE_KEY | none |
| FS-01 | Package Manager Cache Elimination | paths: /var/cache/apt, /var/cache/apk, /root/.cache, /.git, /root/.ssh, /.env (minus the paths the operator allows) | none |
| FS-03 | Exclusion of Build Compilers from Production | binaries: gcc, g++, make (minus the binaries the operator allows) | none |
| FS-04 | SUID/SGID Privilege Escalation Vectors | none | none |
| EXEC-01 | Read-Only Root Filesystem Conformance | none | none |
| EXEC-02 | Dropped Linux Capabilities Conformance | none | none |
| EXEC-03 | Graceful Signal Handling (SIGTERM) | timeout: 5s | none |

A pack excludes a check with its rule ID. The legacy handles are older pack-level IDs that still disable the checks listed next to them; they are exclusion handles, not mappings to a standard. A handle named after a CIS control keeps the control number it had in an older version of the benchmark, so existing exclusion lists keep working. It is a name and says nothing about the numbering of any version.

### NSA/CISA Kubernetes & OpenShift Restricted-v2 Baseline (`PACK-KUBE-HARDENED`)

Select it with `--pack kube`.

Checks for running an image under restrictive Kubernetes or OpenShift settings. The runtime checks show whether the image still starts under them. They do not evaluate a cluster.

| Check | Name | Parameters | Legacy exclusion handles |
|:---|:---|:---|:---|
| SPEC-01 | Non-Root Execution Identity | none | KUBE-01 |
| EXEC-01 | Read-Only Root Filesystem Conformance | none | KUBE-02 |
| EXEC-02 | Dropped Linux Capabilities Conformance | none | KUBE-03 |
| EXEC-05 | Arbitrary Non-Root UID Conformance | uid: 10001 | KUBE-04 |
| EXEC-04 | No-New-Privileges Kernel Contract | none | KUBE-05 |
| EXEC-03 | Graceful Signal Handling (SIGTERM) | timeout: 5s | KUBE-06 |
| SPEC-05 | Non-Privileged Declared Image Ports | skipped when the pack allows privileged ports | KUBE-07 |
| EXEC-08 | Kubernetes PSS Restricted Profile Conformance | none | KUBE-08 |

A pack excludes a check with its rule ID. The legacy handles are older pack-level IDs that still disable the checks listed next to them; they are exclusion handles, not mappings to a standard. A handle named after a CIS control keeps the control number it had in an older version of the benchmark, so existing exclusion lists keep working. It is a name and says nothing about the numbering of any version.

### NIST SP 800-190 Application Container Security Guide (`PACK-NIST-800-190`)

Select it with `--pack nist`.

Checks chosen to reflect themes of NIST SP 800-190 for images. The mapping to the publication is thematic: it has no numbered controls to map to.

| Check | Name | Parameters | Legacy exclusion handles |
|:---|:---|:---|:---|
| SPEC-01 | Non-Root Execution Identity | none | NIST-IMG-1 |
| SPEC-03 | Clean Ambient Environment | disallowed keys: PASSWORD, SECRET, TOKEN, AWS_SECRET | NIST-IMG-2 |
| FS-06 | Private Key Material Scan | none | NIST-IMG-2 |
| FS-03 | Exclusion of Build Compilers from Production | binaries: gcc, g++, make, gdb, strace (minus the binaries the operator allows) | NIST-IMG-3 |
| FS-01 | Package Manager Cache Elimination | paths: /var/cache/apt, /var/cache/apk, /root/.cache (minus the paths the operator allows) | NIST-IMG-3 |
| FS-04 | SUID/SGID Privilege Escalation Vectors | none | NIST-IMG-4 |
| FS-05 | World-Writable File Elimination | none | NIST-IMG-4 |
| EXEC-01 | Read-Only Root Filesystem Conformance | none | NIST-RT-1 |
| EXEC-02 | Dropped Linux Capabilities Conformance | none | NIST-RT-1 |
| EXEC-03 | Graceful Signal Handling (SIGTERM) | timeout: 5s | NIST-RT-1 |

A pack excludes a check with its rule ID. The legacy handles are older pack-level IDs that still disable the checks listed next to them; they are exclusion handles, not mappings to a standard. A handle named after a CIS control keeps the control number it had in an older version of the benchmark, so existing exclusion lists keep working. It is a name and says nothing about the numbering of any version.

### Distroless Image Hardening Pack (`PACK-DISTROLESS`)

Select it with `--pack distroless`.

Checks for images that are meant to ship without a shell or a package manager.

| Check | Name | Parameters | Legacy exclusion handles |
|:---|:---|:---|:---|
| SPEC-01 | Non-Root Execution Identity | none | DISTRO-01 |
| DISTRO-02 | Interactive Shell Elimination | none | none |
| DISTRO-03 | Package Manager Utility Elimination | none | none |
| FS-04 | SUID/SGID Privilege Escalation Vectors | none | DISTRO-04 |
| FS-05 | World-Writable File Elimination | none | DISTRO-04 |
| EXEC-01 | Read-Only Root Filesystem Conformance | none | DISTRO-05 |
| EXEC-02 | Dropped Linux Capabilities Conformance | none | DISTRO-05 |

A pack excludes a check with its rule ID. The legacy handles are older pack-level IDs that still disable the checks listed next to them; they are exclusion handles, not mappings to a standard. A handle named after a CIS control keeps the control number it had in an older version of the benchmark, so existing exclusion lists keep working. It is a name and says nothing about the numbering of any version.

### Image Static Lint Pack (`PACK-IMAGE-LINT`)

Select it with `--pack lint` (alias `image-lint`).

Static checks over the image configuration, the build history and the file tree, chosen to cover the image-level checkpoints of the Dockle linter. The pack starts no container and needs no engine probe and no package inventory. It is a ConUnit profile and not a compliance assessment. Its SPEC-03 uses the suspicious and accepted environment keys of Dockle v0.4.15, and its FS-01 uses the paths of the hygiene pack plus /var/lib/apt/lists. SPEC-09 to SPEC-13, FS-10 to FS-12 are exploratory checks: their limits state where they differ from Dockle on purpose. The names lint and image-lint resolve to this pack.

| Check | Name | Parameters | Legacy exclusion handles |
|:---|:---|:---|:---|
| SPEC-01 | Non-Root Execution Identity | none | none |
| CIS-4.6 | Image HEALTHCHECK | none | none |
| FS-04 | SUID/SGID Privilege Escalation Vectors | none | none |
| SPEC-07 | Instruction Hygiene (COPY over ADD) | none | none |
| SPEC-03 | Clean Ambient Environment | disallowed keys: PASS, PASSWD, PASSWORD, SECRET, KEY, ACCESS, TOKEN; accepted keys: GPG_KEY, GPG_KEYS | none |
| FS-06 | Private Key Material Scan | none | none |
| FS-08 | Account Security (Empty Passwords) | none | none |
| FS-01 | Package Manager Cache Elimination | paths: /var/cache/apt, /var/cache/apk, /root/.cache, /.git, /root/.ssh, /.env, /var/lib/apt/lists (minus the paths the operator allows) | none |
| SPEC-09 | Update Instruction Combined With Install | package managers: apt-get, apt | none |
| SPEC-10 | No Sudo in the Build History | none | none |
| SPEC-11 | No Distribution Upgrade in the Build History | commands: apt-get dist-upgrade, apt dist-upgrade | none |
| SPEC-12 | No Sensitive Host Paths as Volumes | paths: /dev, /proc, /sys and below | none |
| SPEC-13 | Explicit Non-Latest Image Reference | rejected: no tag and no digest, tag latest | none |
| FS-10 | Unique Account and Group IDs | files: /etc/passwd, /etc/group | none |
| FS-11 | No Development, Editor, Cache or Cloud Leftovers | directories: .cache, .aws, .azure, .gcp, .git, .vscode, .idea, .npm; files: Dockerfile, docker-compose.yml, .vimrc, .DS_Store; skipped trees: node_modules, vendor | none |
| FS-12 | No Credential-Named Files | file names: credentials.json, credential.json, credentials, credential, password.txt, id_rsa, id_dsa, id_ecdsa, id_ed25519, secret_token.rb, carrierwave.rb, omniauth.rb, settings.py, database.yml, credentials.xml, .env; extensions: .secret, .ovpn, .private_key, .cscfg, .rdp, .mdf, .sdf, .bek, .tpm, .fve, .jks, .psafe3, .agilekeychain, .keychain, .pcap, .gnucache | none |

A pack excludes a check with its rule ID. The legacy handles are older pack-level IDs that still disable the checks listed next to them; they are exclusion handles, not mappings to a standard. A handle named after a CIS control keeps the control number it had in an older version of the benchmark, so existing exclusion lists keep working. It is a name and says nothing about the numbering of any version.

## Rules

### Tier 1: Specification

#### CIS-4.6: Image HEALTHCHECK

- Standard: no standard control (custom ConUnit check)
- Scope: metadata_declaration
- Packs: hardening, lint
- Oracle: Passes when the image config defines a HEALTHCHECK whose test is not NONE and not empty.
- Evidence: None beyond the verdict.
- Limits: Presence only. It does not run the health check or judge its quality.

#### SPEC-01: Non-Root Execution Identity

- Standard: no standard control (custom ConUnit check)
- Scope: metadata_declaration
- Packs: hardening, hygiene, kube, nist, distroless, lint
- Oracle: Reads USER from the image config. A numeric UID other than 0 passes. A user name is resolved through the final image /etc/passwd. An empty USER, root and any name that resolves to UID 0 fail.
- Evidence: The configured user and the resolved UID, in the message.
- Limits: Observes the default user only. A process can change user at run time (gosu, su-exec) and an operator can pass --user. UNVERIFIED when a name cannot be resolved from complete /etc/passwd evidence.

#### SPEC-02: Deterministic Entrypoint or Command

- Standard: no standard control (custom ConUnit check)
- Scope: metadata_declaration
- Packs: hygiene
- Oracle: Passes when the image config defines ENTRYPOINT or CMD.
- Evidence: The configured entrypoint and command, in the message.
- Limits: Presence only. It does not examine whether the command starts a useful or stable process.

#### SPEC-03: Clean Ambient Environment

- Standard: no standard control (custom ConUnit check)
- Scope: metadata_declaration
- Packs: hardening, hygiene, nist, lint
- Oracle: Matches the names of the image ENV variables against the pack's disallowed keys (case-insensitive, pattern or substring) and the values against AWS access key, GitHub token, Slack token and PEM private key patterns.
- Evidence: The offending variable names and the pattern that matched, in the message. Values are not recorded.
- Limits: Name matching also flags variables that hold no secret (a path to a token file, for example). Value matching knows only the listed token formats. Only ENV in the image config is read, not build arguments, files or Dockerfile text.

#### SPEC-04: Image Size Hygiene Budget

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: none
- Oracle: Compares the engine-reported image size with a limit in MB that the caller supplies.
- Evidence: The size and the limit, in the message.
- Limits: The limit is a policy choice, not a standard. The engine-reported size can differ between engines and storage drivers. No shipped pack uses this check.

#### SPEC-05: Non-Privileged Declared Image Ports

- Standard: no standard control (custom ConUnit check)
- Scope: metadata_declaration
- Packs: hardening, kube
- Oracle: Parses the EXPOSE declarations of the image config. A port below 1024, or a declaration that cannot be parsed, fails.
- Evidence: The offending declarations, sorted, in the message.
- Limits: Declared ports only. Neither listeners nor the ports published at run time are observed, and the related benchmark recommendation concerns ports mapped at run time.

#### SPEC-06: Dangling Debug Port Exclusion

- Standard: no standard control (custom ConUnit check)
- Scope: metadata_declaration
- Packs: hardening
- Oracle: Fails when the image config declares one of the ports 5005, 9229, 2375, 22 or 6006, or a declaration that cannot be parsed.
- Evidence: The offending ports, in the message.
- Limits: Declared ports only. The port numbers are conventions, and an application can legitimately use one of them.

#### SPEC-07: Instruction Hygiene (COPY over ADD)

- Standard: no standard control (custom ConUnit check)
- Scope: metadata_declaration
- Packs: hardening, lint
- Oracle: Reads the OCI image history. Every ADD instruction fails except the base image rootfs import, which is the first layer-producing history entry in the legacy form 'ADD file:<digest> in /' or the BuildKit form 'ADD <name>.tar* / # buildkit'.
- Evidence: The reported ADD instructions, in the message.
- Limits: Sees only the instructions the history records. Multi-stage builds, squashed images and history that was stripped hide instructions. UNVERIFIED (EVIDENCE_INCOMPLETE) when the history is missing or malformed.

#### SPEC-08: Supply-Chain OCI Provenance Annotations

- Standard: no standard control (custom ConUnit check)
- Scope: metadata_declaration
- Packs: none
- Oracle: Passes when the image labels org.opencontainers.image.source and org.opencontainers.image.revision (or the keys the caller names) are present and not empty.
- Evidence: The missing label names, in the message.
- Limits: Presence only. It does not check that a label is true or that it resolves.

#### SPEC-09: Update Instruction Combined With Install

- Standard: no standard control (custom ConUnit check)
- Scope: metadata_declaration
- Packs: lint
- Oracle: Reads the OCI image history. Only RUN steps are scanned: the legacy form '/bin/sh -c <script>' (also with a '|N NAME=value' build-argument prefix), the BuildKit form 'RUN <script> # buildkit' and a bare command text. Metadata instructions (ENV, CMD, ENTRYPOINT, COPY, ADD, LABEL, HEALTHCHECK and so on) and comment entries are not scanned. A script is split into simple commands on &&, ||, ;, |, a single &, parentheses, backticks and newlines, with quotes, comments, backslash continuations, here-documents and the script argument of sh -c handled. A word counts as a command only in command position, after leading variable assignments, redirections, the keywords if, then, else, elif, do, while, until, ! and time, and the wrappers env, exec, command and nohup. A step fails when it runs apt-get or apt with the subcommand update and no later command of the same step runs install or upgrade of the same package manager. apt-get and apt share one package index and count as one manager. Each update needs its own later install or upgrade. Corresponds to the Dockle checkpoint CIS-DI-0007.
- Evidence: The offending commands with the 1-based number of their history entry, at most five in the message with the count of the rest. The history text is not stored.
- Limits: Covers the apt family only: apk, yum, dnf and zypper index updates are not seen. An install in a later RUN step does not count, which is the point of the check. dist-upgrade and full-upgrade do not count as an upgrade, as in Dockle. Intended differences from Dockle v0.4.15, which splits a history line on && and on single spaces only: it finds an update in a line only when the words are separated by spaces, it reads words inside quoted text and arguments such as 'echo apt-get update', it scans every history entry including metadata instructions, it does not recognize 'update;' as the word update because the semicolon stays on the word, and it stops at the first install or upgrade after the first update, so a second update at the end of a step is reported here and not there. Sees only what the history records: squashed images, multi-stage builds, builds that strip the history and scripts that an entrypoint runs later are not seen. The parse is a heuristic for shell text: variables that hold a command name, eval, xargs, find -exec, command substitution inside double quotes and aliases are not resolved. UNVERIFIED (EVIDENCE_INCOMPLETE) when the history is missing, empty or malformed (an empty entry, an unterminated quote or here-document) and nothing was found. The check is exploratory until adjudication shows adequate precision.

#### SPEC-10: No Sudo in the Build History

- Standard: no standard control (custom ConUnit check)
- Scope: metadata_declaration
- Packs: lint
- Oracle: Reads the OCI image history. Only RUN steps are scanned: the legacy form '/bin/sh -c <script>' (also with a '|N NAME=value' build-argument prefix), the BuildKit form 'RUN <script> # buildkit' and a bare command text. Metadata instructions (ENV, CMD, ENTRYPOINT, COPY, ADD, LABEL, HEALTHCHECK and so on) and comment entries are not scanned. A script is split into simple commands on &&, ||, ;, |, a single &, parentheses, backticks and newlines, with quotes, comments, backslash continuations, here-documents and the script argument of sh -c handled. A word counts as a command only in command position, after leading variable assignments, redirections, the keywords if, then, else, elif, do, while, until, ! and time, and the wrappers env, exec, command and nohup. A step fails when sudo, or a path ending in /sudo, is the command word of a simple command. Corresponds to the Dockle checkpoint DKL-DI-0001.
- Evidence: The offending commands with the 1-based number of their history entry, at most five in the message with the count of the rest. The history text is not stored.
- Limits: Command position only: installing the package ('apt-get install sudo') and naming sudo as an argument ('echo sudo', 'which sudo', 'command -v sudo') are no findings, and neither is a sudo behind another wrapper such as xargs, find -exec or ssh. Intended difference from Dockle v0.4.15, which matches the word sudo anywhere between spaces in the text of every history entry and so also reports those uses, metadata instructions included. A sudo that only an entrypoint script or a CMD runs is outside the history. Sees only what the history records: squashed images, multi-stage builds, builds that strip the history and scripts that an entrypoint runs later are not seen. The parse is a heuristic for shell text: variables that hold a command name, eval, xargs, find -exec, command substitution inside double quotes and aliases are not resolved. UNVERIFIED (EVIDENCE_INCOMPLETE) when the history is missing, empty or malformed (an empty entry, an unterminated quote or here-document) and nothing was found. The check is exploratory until adjudication shows adequate precision.

#### SPEC-11: No Distribution Upgrade in the Build History

- Standard: no standard control (custom ConUnit check)
- Scope: metadata_declaration
- Packs: lint
- Oracle: Reads the OCI image history. Only RUN steps are scanned: the legacy form '/bin/sh -c <script>' (also with a '|N NAME=value' build-argument prefix), the BuildKit form 'RUN <script> # buildkit' and a bare command text. Metadata instructions (ENV, CMD, ENTRYPOINT, COPY, ADD, LABEL, HEALTHCHECK and so on) and comment entries are not scanned. A script is split into simple commands on &&, ||, ;, |, a single &, parentheses, backticks and newlines, with quotes, comments, backslash continuations, here-documents and the script argument of sh -c handled. A word counts as a command only in command position, after leading variable assignments, redirections, the keywords if, then, else, elif, do, while, until, ! and time, and the wrappers env, exec, command and nohup. A step fails when a simple command is apt-get or apt (or a path ending in either) whose subcommand is dist-upgrade. Options before the subcommand, such as -y and -o Name=value, are skipped. Corresponds to the Dockle checkpoint DKL-DI-0003.
- Evidence: The offending commands with the 1-based number of their history entry, at most five in the message with the count of the rest. The history text is not stored.
- Limits: apt full-upgrade does the same work as dist-upgrade and is not reported, as in Dockle. Other package managers are not covered. Intended difference from Dockle v0.4.15, which reports a history line when the words apt-get or apt and dist-upgrade occur together between two && separators, in any order and with any other words, so it also reports an echo of those words; here the subcommand must belong to a real apt-get or apt command. Sees only what the history records: squashed images, multi-stage builds, builds that strip the history and scripts that an entrypoint runs later are not seen. The parse is a heuristic for shell text: variables that hold a command name, eval, xargs, find -exec, command substitution inside double quotes and aliases are not resolved. UNVERIFIED (EVIDENCE_INCOMPLETE) when the history is missing, empty or malformed (an empty entry, an unterminated quote or here-document) and nothing was found. The check is exploratory until adjudication shows adequate precision.

#### SPEC-12: No Sensitive Host Paths as Volumes

- Standard: no standard control (custom ConUnit check)
- Scope: metadata_declaration
- Packs: lint
- Oracle: Reads the volumes that the image config declares (VOLUME instructions) from the engine inspection of the image. Each path is cleaned (repeated separators, dot and dot-dot components, a trailing slash). Fails when a cleaned path is /dev, /proc or /sys or lies below one of them. Corresponds to the Dockle checkpoint DKL-DI-0002.
- Evidence: The offending volume paths as declared, sorted, in the message and in the evidence paths.
- Limits: Declared volumes only: mounts given at run time (docker run -v /sys:/sys) cannot be seen from the image, as Dockle also states. Intended difference from Dockle v0.4.15, which compares each declared path with the three names exactly: a child such as /proc/sys and a spelling such as /proc/ are reported here and not there. A declared path that is empty or not absolute cannot be placed in the tree, so when nothing else fails the result is UNVERIFIED (EVIDENCE_INCOMPLETE), as it is when the engine inspection data is unavailable. Exploratory.

#### SPEC-13: Explicit Non-Latest Image Reference

- Standard: no standard control (custom ConUnit check)
- Scope: metadata_declaration
- Packs: lint
- Oracle: Reads the image reference exactly as it was requested on the command line or in the dataset. Passes for a reference with a digest (whatever tag comes with it), for an image ID (64 hexadecimal characters, with or without the prefix sha256:) and for an explicit tag other than latest. Fails when the reference has no tag and no digest, which the engine resolves to latest, or when the tag is latest. Corresponds to the Dockle checkpoint DKL-DI-0006.
- Evidence: The requested reference and how it pins the content, in the message.
- Limits: Judges the spelling of the request, not the image. An explicit tag such as 1.2 is still mutable, so a PASS for a tag does not say that the content cannot change; only a digest does. A local archive has no image reference, so the result is UNVERIFIED (EVIDENCE_INCOMPLETE) for the tarball source, and for a reference that cannot be parsed. Dockle v0.4.15 evaluates its latest-tag checkpoint only when it is given an image name, never when it reads an archive with --input, so a comparison over exported archives cannot reproduce this check. Like this check, Dockle reads a name without a tag as latest and does not report a digest-pinned reference. Exploratory.

### Tier 2: Filesystem Hygiene

#### DISTRO-02: Interactive Shell Elimination

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: distroless
- Oracle: Fails when sh, bash, zsh, dash, ash, csh or tcsh exists in /bin, /usr/bin, /usr/local/bin, /sbin or /usr/sbin of the merged filesystem.
- Evidence: The shell names that were found.
- Limits: Name based and limited to the listed shells. A path counts even if it is a link to a multi-call binary.

#### DISTRO-03: Package Manager Utility Elimination

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: distroless
- Oracle: Fails when apk, apt, apt-get, dpkg, yum, rpm, dnf, microdnf, pacman, pip or npm exists in the standard binary directories of the merged filesystem.
- Evidence: The utility names that were found.
- Limits: Name based and limited to the listed utilities.

#### FS-01: Package Manager Cache Elimination

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: hygiene, nist, lint
- Oracle: Checks that no path of a fixed list holds content in the merged filesystem of the final image, rebuilt from the layers with whiteouts applied. A path holds content when it is a file or a link (a file of zero bytes included, because then the path itself is the finding), or a directory with at least one entry below it, at any depth, that is neither a directory nor a regular file of zero bytes. An empty directory does not count, because base images ship empty directories such as /var/cache/apk and /var/lib/apt/lists. A directory that holds only empty files does not count either, because apt leaves an empty lock file under /var/cache/apt/archives after every run. The list of a pack is shown in its table below.
- Evidence: The paths that hold content, in the message.
- Limits: A fixed list: other caches are not seen. A zero-byte file that lies below a listed directory is ignored, so a cache that consists of empty marker files only is not seen, and a hard link below a listed directory always counts. Without a filesystem index the engine probe reports every existing path, empty or not.

#### FS-03: Exclusion of Build Compilers from Production

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: hygiene, nist
- Oracle: Checks the file names of a fixed list of build tools (for example gcc, g++, make) in /bin, /usr/bin, /usr/local/bin, /sbin and /usr/sbin of the merged filesystem.
- Evidence: The tools that were found, in the message.
- Limits: Name based. A renamed or versioned binary (gcc-12) is not seen, other toolchains are not covered, and a build tool that the application needs counts as a failure.

#### FS-04: SUID/SGID Privilege Escalation Vectors

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: hardening, hygiene, nist, distroless, lint
- Oracle: Fails when the merged filesystem holds a regular file with the setuid or setgid mode bit. A hard link takes the mode of the file it names in the same layer, because both are one inode.
- Evidence: The paths, sorted, in the message.
- Limits: Some executables legitimately need the bits. The check cannot know which do, so every such file counts. Mode bits are those recorded in the layers. A hard link whose target is not a file of the same layer has no readable mode: when nothing else fails the result is UNVERIFIED (EVIDENCE_INCOMPLETE), because the OCI image specification warns that such links may not extract and a lower layer's mode is not kept.

#### FS-05: World-Writable File Elimination

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: hardening, nist, distroless
- Oracle: Fails when the merged filesystem holds a regular file whose mode has the world-writable bit. Directories and symbolic links are not counted. A hard link takes the mode of the file it names in the same layer, because both are one inode.
- Evidence: The paths, sorted, in the message.
- Limits: Mode bits as recorded in the layers, not effective permissions (ACLs, mount options and user namespaces are not considered). A hard link whose target is not a file of the same layer has no readable mode: when nothing else fails the result is UNVERIFIED (EVIDENCE_INCOMPLETE).

#### FS-06: Private Key Material Scan

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: hardening, nist, lint
- Oracle: Reads the content of files named *.key, *.pem, id_rsa, id_ed25519, id_dsa or id_ecdsa (up to 1 MiB) and looks for a PEM or OpenSSH private-key block. Findings under testdata, test, tests, fixtures, fixture, examples or example path components, and Debian snakeoil files, are fixture candidates and are counted separately. Only the other findings fail the check.
- Evidence: Finding paths and fixture candidate paths, sorted. The list of fixture candidates is capped at 200 entries; the message states the full counts.
- Limits: Covers the named file patterns and PEM/OpenSSH formats only, not arbitrary files or other encodings. It does not know whether a key is a test key, and the fixture rule is a path heuristic. UNVERIFIED when a candidate is truncated or uses an unsupported encoding.

#### FS-07: Development and Test Harness Leakage

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: hardening
- Oracle: Matches the exact file names phpunit.xml, phpunit.xml.dist, jest.config.js and pytest.ini and the whole path component sequences testdata, tests/phpunit and tests/assets. A test directory is reported once, as the shallowest match. Matches under fixture-like components are fixture candidates, counted separately. Only the other matches fail the check.
- Evidence: Finding paths and fixture candidate paths, sorted.
- Limits: A fixed list of four file names and three directory patterns, so most test frameworks are not covered. The fixture split is a path heuristic. The check is exploratory unless adjudication shows adequate precision.

#### FS-08: Account Security (Empty Passwords)

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: hardening, lint
- Oracle: Reads the final /etc/passwd and /etc/shadow (up to 1 MiB each). An account with an empty password field fails.
- Evidence: The account names, sorted.
- Limits: Reads the account files of the final image only. It does not judge hash strength. UNVERIFIED (EVIDENCE_INCOMPLETE) when a file is missing, oversized or malformed.

#### FS-09: System Directory Ownership Hygiene

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: hardening
- Oracle: Fails when a regular file in /bin, /usr/bin, /sbin or /usr/sbin has an owner UID other than 0 in the layer metadata. A hard link takes the owner of the file it names in the same layer, because both are one inode.
- Evidence: The paths with their UIDs, sorted.
- Limits: The owner recorded in the layers. User namespace remapping and later ownership changes by the runtime are not considered. A hard link in one of the four directories whose target is not a file of the same layer has no readable owner: when nothing else fails the result is UNVERIFIED (EVIDENCE_INCOMPLETE). Unresolved links elsewhere in the tree do not affect this check.

#### FS-10: Unique Account and Group IDs

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: lint
- Oracle: Reads the final /etc/passwd and /etc/group (up to 1 MiB each, with whiteouts and replacements applied). Fails when two different account names share one UID in /etc/passwd, or two different group names share one GID in /etc/group. Corresponds to the Dockle checkpoint DKL-LI-0002.
- Evidence: The shared IDs with their names, sorted, in the message and in the evidence paths.
- Limits: A name that is listed twice with the same ID is one account and not a collision. Dockle v0.4.15 reports every repeated ID, that case included, takes the third field of every line without validating the record, and does not skip comment lines in /etc/passwd. A shared ID can be intended, and the check cannot tell which. Only the two files are read: accounts that NSS modules, LDAP or the container runtime provide are not seen. UNVERIFIED (EVIDENCE_INCOMPLETE) when either file is missing, not a regular file (a hard link included), oversized or malformed, or holds no records, and no collision was found in the part that was read. Exploratory.

#### FS-11: No Development, Editor, Cache or Cloud Leftovers

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: lint
- Oracle: Looks at every path of the merged filesystem of the final image. Fails when a path has a component named .cache, .aws, .azure, .gcp, .git, .vscode, .idea, .npm, or when a non-directory entry is named Dockerfile, docker-compose.yml, .vimrc, .DS_Store. Entries below a node_modules, vendor directory are skipped, while a leftover above such a directory is still reported. A matching directory is reported once, at its shallowest occurrence, and entries below a reported directory are not listed again. Corresponds to the Dockle checkpoint DKL-LI-0003.
- Evidence: The reported directories and files, sorted, in the message and in the evidence paths (at most 200; the message states the full count).
- Limits: Name based and case sensitive, so it also reports directories that are expected in a development image and empty ones, and it never judges content. Intended differences from Dockle v0.4.15: Dockle sees regular files, symbolic links and hard links only, and reports a directory only through a file that is its direct child, so an empty directory or one that holds only subdirectories is reported here and not there. Dockle applies its node_modules and vendor skip to directory matches only and tests the substring node_modules/ anywhere in the path, so it still reports a Dockerfile below node_modules, which is skipped here; here the skip compares whole components. A file named .git (a submodule pointer) counts as a component here. A hard link counts as a file under its own name and its target is not needed. UNVERIFIED (EVIDENCE_INCOMPLETE) when the index holds no entries. Exploratory.

#### FS-12: No Credential-Named Files

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: lint
- Oracle: Looks at every non-directory entry of the merged filesystem. Fails when the file name is one of credentials.json, credential.json, credentials, credential, password.txt, id_rsa, id_dsa, id_ecdsa, id_ed25519, secret_token.rb, carrierwave.rb, omniauth.rb, settings.py, database.yml, credentials.xml, .env, or when its extension, taken from the last dot of the name, is one of .secret, .ovpn, .private_key, .cscfg, .rdp, .mdf, .sdf, .bek, .tpm, .fve, .jks, .psafe3, .agilekeychain, .keychain, .pcap, .gnucache. Findings under testdata, test, tests, fixtures, fixture, examples or example path components and Debian snakeoil files are fixture candidates (the rule of FS-06), counted separately; only the other findings fail the check. Corresponds to the file name part of the Dockle checkpoint CIS-DI-0010.
- Evidence: Finding paths and fixture candidate paths, sorted (each list capped at 200 in the evidence; the message states the full counts).
- Limits: File names only: the content is not read, so an empty file and a documentation sample count, and a credential kept under another name is not seen (FS-06 reads the content of key files). settings.py, credentials and database.yml are common names of files that hold no secret, so low precision is expected. Names and extensions are case sensitive, as in Dockle. A symbolic link or hard link named like a credential file counts under its own name. Dockle v0.4.15 also matches NAME=value words of the build history for CIS-DI-0010 and can suppress names with accept-file options; that part is covered by SPEC-03 over the final environment, and this check has no suppression list besides the fixture rule. No CIS control number is stated for this check. UNVERIFIED (EVIDENCE_INCOMPLETE) when the index holds no entries. Exploratory.

### Tier 3: Execution Contract

#### EXEC-01: Read-Only Root Filesystem Conformance

- Standard: no standard control (custom ConUnit check)
- Scope: runtime_compatibility
- Packs: hardening, hygiene, kube, nist, distroless
- Oracle: Baseline-controlled run. The image's own entrypoint is started once with only the defensive flags (--network=none, --pids-limit=256) and a fixed mock environment, and observed for the window W (default 3 s). If that baseline is not running at the end of W the result is UNVERIFIED (BASELINE_FAILED, or NOT_OBSERVABLE when it exited 0). Otherwise the treatment is started with the same flags plus its own: PASS if it is also running at the end of W, FAIL if not. Treatment: --read-only with a 64 MiB writable tmpfs at /tmp.
- Evidence: Baseline and treatment state (running, exited0, exited_nonzero, start_failed), exit codes, the window W and the last 50 log lines. A keyword hint may be present; it is never a diagnosis.
- Limits: FAIL means the container was not running at the end of W under this profile although the baseline was. It is not a defect claim and not a root cause, and the check says nothing about the image's behavior after W or under other flags. Latency is bounded below by W and is not a performance result. The related hardening recommendation concerns how an operator runs a container. This check shows whether the image still starts that way.

#### EXEC-02: Dropped Linux Capabilities Conformance

- Standard: no standard control (custom ConUnit check)
- Scope: runtime_compatibility
- Packs: hardening, hygiene, kube, nist, distroless
- Oracle: Baseline-controlled run. The image's own entrypoint is started once with only the defensive flags (--network=none, --pids-limit=256) and a fixed mock environment, and observed for the window W (default 3 s). If that baseline is not running at the end of W the result is UNVERIFIED (BASELINE_FAILED, or NOT_OBSERVABLE when it exited 0). Otherwise the treatment is started with the same flags plus its own: PASS if it is also running at the end of W, FAIL if not. Treatment: --cap-drop=ALL.
- Evidence: Baseline and treatment state (running, exited0, exited_nonzero, start_failed), exit codes, the window W and the last 50 log lines. A keyword hint may be present; it is never a diagnosis.
- Limits: FAIL means the container was not running at the end of W under this profile although the baseline was. It is not a defect claim and not a root cause, and the check says nothing about the image's behavior after W or under other flags. Latency is bounded below by W and is not a performance result. The related hardening recommendation concerns how an operator runs a container. This check shows whether the image still starts without capabilities, not which capability it needs.

#### EXEC-03: Graceful Signal Handling (SIGTERM)

- Standard: no standard control (custom ConUnit check)
- Scope: runtime_compatibility
- Packs: hygiene, kube, nist
- Oracle: Same baseline gate as the other Tier 3 checks. A container that is running at the end of W receives SIGTERM. It passes when it exits with code 0 or 143 within the timeout (5 s in the shipped packs) and fails when it stays running or exits with another code.
- Evidence: Baseline and treatment state (running, exited0, exited_nonzero, start_failed), exit codes, the window W and the last 50 log lines. A keyword hint may be present; it is never a diagnosis.
- Limits: Observes one signal after the window under the baseline profile. An image whose entrypoint is a shell may forward or swallow the signal for reasons that depend on the process tree, which the check does not examine.

#### EXEC-04: No-New-Privileges Kernel Contract

- Standard: no standard control (custom ConUnit check)
- Scope: runtime_compatibility
- Packs: hardening, kube
- Oracle: Baseline-controlled run. The image's own entrypoint is started once with only the defensive flags (--network=none, --pids-limit=256) and a fixed mock environment, and observed for the window W (default 3 s). If that baseline is not running at the end of W the result is UNVERIFIED (BASELINE_FAILED, or NOT_OBSERVABLE when it exited 0). Otherwise the treatment is started with the same flags plus its own: PASS if it is also running at the end of W, FAIL if not. Treatment: --security-opt=no-new-privileges:true.
- Evidence: Baseline and treatment state (running, exited0, exited_nonzero, start_failed), exit codes, the window W and the last 50 log lines. A keyword hint may be present; it is never a diagnosis.
- Limits: FAIL means the container was not running at the end of W under this profile although the baseline was. It is not a defect claim and not a root cause, and the check says nothing about the image's behavior after W or under other flags. Latency is bounded below by W and is not a performance result. The related hardening recommendation concerns how an operator runs a container. This check shows whether the image still starts that way.

#### EXEC-05: Arbitrary Non-Root UID Conformance

- Standard: no standard control (custom ConUnit check)
- Scope: runtime_compatibility
- Packs: kube
- Oracle: Baseline-controlled run. The image's own entrypoint is started once with only the defensive flags (--network=none, --pids-limit=256) and a fixed mock environment, and observed for the window W (default 3 s). If that baseline is not running at the end of W the result is UNVERIFIED (BASELINE_FAILED, or NOT_OBSERVABLE when it exited 0). Otherwise the treatment is started with the same flags plus its own: PASS if it is also running at the end of W, FAIL if not. Treatment: --user 10001:10001 (the UID of the shipped Kubernetes pack).
- Evidence: Baseline and treatment state (running, exited0, exited_nonzero, start_failed), exit codes, the window W and the last 50 log lines. A keyword hint may be present; it is never a diagnosis.
- Limits: FAIL means the container was not running at the end of W under this profile although the baseline was. It is not a defect claim and not a root cause, and the check says nothing about the image's behavior after W or under other flags. Latency is bounded below by W and is not a performance result. It models the arbitrary-UID rule of OpenShift restricted SCC without the group ownership that the platform adds.

#### EXEC-06: HTTP Operational Readiness Contract

- Standard: no standard control (custom ConUnit check)
- Scope: runtime_compatibility
- Packs: none
- Oracle: Starts the container with the given port published on a free local port and polls the given path until the expected status or a timeout.
- Evidence: The last status or error, in the message.
- Limits: Not baseline controlled, and not part of any shipped pack. The result depends on the port, path and timeout the caller chooses.

#### EXEC-07: Resource Constraint Conformance

- Standard: no standard control (custom ConUnit check)
- Scope: runtime_compatibility
- Packs: hardening
- Oracle: Baseline-controlled run. The image's own entrypoint is started once with only the defensive flags (--network=none, --pids-limit=256) and a fixed mock environment, and observed for the window W (default 3 s). If that baseline is not running at the end of W the result is UNVERIFIED (BASELINE_FAILED, or NOT_OBSERVABLE when it exited 0). Otherwise the treatment is started with the same flags plus its own: PASS if it is also running at the end of W, FAIL if not. Treatment: --memory=256m. The PID limit is part of the baseline profile, so the treatment differs from the baseline by memory only.
- Evidence: Baseline and treatment state (running, exited0, exited_nonzero, start_failed), exit codes, the window W and the last 50 log lines. A keyword hint may be present; it is never a diagnosis.
- Limits: FAIL means the container was not running at the end of W under this profile although the baseline was. It is not a defect claim and not a root cause, and the check says nothing about the image's behavior after W or under other flags. Latency is bounded below by W and is not a performance result. The 256 MiB limit is a property of the profile: a different limit can give a different verdict.

#### EXEC-08: Kubernetes PSS Restricted Profile Conformance

- Standard: Kubernetes Pod Security Standards ("Restricted profile (container runtime settings)"), mapping approximate
- Scope: runtime_compatibility
- Packs: kube
- Oracle: Baseline-controlled run. The image's own entrypoint is started once with only the defensive flags (--network=none, --pids-limit=256) and a fixed mock environment, and observed for the window W (default 3 s). If that baseline is not running at the end of W the result is UNVERIFIED (BASELINE_FAILED, or NOT_OBSERVABLE when it exited 0). Otherwise the treatment is started with the same flags plus its own: PASS if it is also running at the end of W, FAIL if not. Treatment: read-only root with a 64 MiB tmpfs at /tmp, --cap-drop=ALL, no-new-privileges and --user 10001:10001 together.
- Evidence: Baseline and treatment state (running, exited0, exited_nonzero, start_failed), exit codes, the window W and the last 50 log lines. A keyword hint may be present; it is never a diagnosis.
- Limits: FAIL means the container was not running at the end of W under this profile although the baseline was. It is not a defect claim and not a root cause, and the check says nothing about the image's behavior after W or under other flags. Latency is bounded below by W and is not a performance result. Only four of the settings of the Restricted profile are applied. The profile also constrains volumes, seccomp and other pod fields that a container run cannot show.

### Tier 4: Supply Chain

#### SUP-01: Prohibited Network Reconnaissance Tools

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: none
- Oracle: Generates a package inventory with Syft (run once per image and cached) and fails when a package name of the caller's list is present, compared case-insensitively.
- Evidence: The prohibited package names that were found, in the message.
- Limits: Only as complete as the Syft inventory. UNVERIFIED (TOOL_UNAVAILABLE) when Syft is missing or fails. No shipped pack uses this check.

#### SUP-02: Cryptographic Image Provenance & Signature

- Standard: no standard control (custom ConUnit check)
- Scope: metadata_declaration
- Packs: hardening
- Oracle: Verifies the signature of the immutable image reference with the verifier and trust policy that the caller configures (a cosign key, or a keyless identity and issuer).
- Evidence: The verifier error, in the message, when verification fails.
- Limits: UNVERIFIED (NO_TRUST_POLICY) whenever no trust policy is configured, which is the default, so the result is excluded from prevalence statistics unless a policy is given. It does not cover the Docker Content Trust setting of the scanning host.

#### SUP-03: SPDX License Compliance

- Standard: no standard control (custom ConUnit check)
- Scope: image_content
- Packs: none
- Oracle: Reads the package licenses from the cached Syft inventory and fails when a license is outside the allowlist (default Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0). When no license is violated but a package has no or unparsable license metadata, the result is UNVERIFIED. A violation takes precedence.
- Evidence: The violating packages with their licenses and the packages without usable metadata, sorted, in the message.
- Limits: Only as complete as the Syft license metadata. The allowlist is a policy choice. No shipped pack uses this check.
