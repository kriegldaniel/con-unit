# ConUnit

ConUnit is a research prototype that tests OCI container images. It reads an image without a Docker daemon, checks it in four tiers, and reports each check as PASS, FAIL or UNVERIFIED, with a reason and the evidence behind the outcome. Checks are available through a Go API (xUnit style) and through a command line with rule packs.

Status: research code that goes with a paper. The evaluation results are not part of this branch. The replication package of the final run, made from the tag `eval-v1`, is on the branch [`replication-eval-v1`](https://github.com/kriegldaniel/con-unit/tree/replication-eval-v1).

Project page with a screencast: https://kriegldaniel.github.io/con-unit/

## What it checks

- Tier 1, specification: user, entrypoint, environment, declared ports, build history, health check.
- Tier 2, filesystem: caches, build tools, setuid and setgid bits, world-writable files, private keys, account files, file ownership.
- Tier 3, runtime: the image is started once with only defensive flags as a baseline, then again under one restriction at a time (read-only root filesystem, dropped capabilities, no-new-privileges, a memory limit). A check fails only if the baseline survived the observation window and the restricted run did not. Controlled variants then attribute a failure to a capability or mount.
- Tier 4, supply chain: package and license checks from an SBOM. Tier 4 is an interface only and is not part of the evaluation.

## Limits to keep in mind

- The hardening profile is informed by topics of the CIS Docker Benchmark. No check states a control number, because the numbers were not confirmed against the official document (see `docs/DEVIATIONS.md`, DEV-15). It is not a CIS compliance assessment. See `docs/RULES.md`.
- Other image linters, for example Dockle and the Anchore CIS policy pack, cover much of what Tier 1 and Tier 2 check. The evaluation compares ConUnit with Dockle on the same images.
- Tier 3 is a short liveness proxy. A FAIL means that the container was not running at the end of the window under the restriction although the baseline was. It is not a defect claim and not a root cause.
- Findings about a sample of images are descriptive. The evaluation sample is a convenience sample of digest-pinned Docker Official Images.

## Quick start

You need Nix with flakes and a running container engine, Podman or Docker. Tier 3 starts the image's own entrypoint, so run the checks on a disposable machine. With `direnv` the development shell also loads on entering the directory.

These steps were run from a fresh clone on 2026-11-20 (rootless Podman 5.8.1, linux/arm64):

```sh
git clone https://github.com/kriegldaniel/con-unit.git
cd con-unit
nix develop                                  # Go, just and the other tools
go mod download                              # once, `just test` runs with GOPROXY=off
just test                                    # offline unit tests
just build                                   # builds bin/con-unit
./bin/con-unit test alpine:latest            # the hardening profile on one image
./bin/con-unit test alpine:latest --pack hygiene
./bin/con-unit rules                         # the generated rule reference
```

Without `go mod download`, `just test` fails in a fresh clone, because the module cache is empty and module lookup is disabled.

`./bin/con-unit test alpine:latest` exits with code 1 when a check fails or is unverified. For `alpine:latest` in that run, `SPEC-01` and `CIS-4.6` failed, and the four runtime checks were `UNVERIFIED` because the baseline exits with code 0 before the observation window ends. The image moves over time, so details can differ.

To build exactly the evaluated version, clone with `--branch eval-v1`. At the time of writing, `main` differs from that tag only in documentation.

Engine-backed tests and the evaluation commands are listed in `justfile` and in `ONBOARDING.md`.

## Module path

The Go module is declared as `github.com/con-unit/con-unit`. Build from a clone as above. `go install github.com/kriegldaniel/con-unit/cmd/con-unit@eval-v1` fails with a module path mismatch, and other Go modules cannot import these packages under this repository's path.

## Documentation

- `docs/RULES.md`: every check with its oracle, evidence, limits and standard mapping, generated from the code.
- `docs/ANALYSIS_PLAN.md`: the evaluation protocol, written before any data, with the decision rules.
- `docs/DEVIATIONS.md`: changes to the design after the first version of the plan.
- `docs/CONTRACT.md` and `docs/INTERFACE_V2.md`: the interfaces that the evaluation tools share.
- `ONBOARDING.md`: architecture and directory layout for new contributors.

## Artifact

The replication package of the final run is on the branch `replication-eval-v1`: the study JSON, logs, journal, run manifest and checksums of both runs. Start with its `README.txt`. How the runs are produced and checked is described in `docs/ANALYSIS_PLAN.md`, section 14.

## License

MIT, see `LICENSE`.
