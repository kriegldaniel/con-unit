# ConUnit

ConUnit is a research prototype that tests OCI container images. It reads an image without a Docker daemon, checks it in four tiers, and reports each check as PASS, FAIL or UNVERIFIED, with a reason and the evidence behind the outcome. Checks are available through a Go API (xUnit style) and through a command line with rule packs.

Status: research code that goes with a paper. This repository contains no evaluation result. Results are generated from the files of a tagged final run and appear only in the paper and its artifact.

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

The project uses Nix flakes. With `direnv` the development shell loads on entering the directory.

```sh
just test                                    # offline unit tests
just build                                   # builds bin/con-unit
./bin/con-unit test alpine:latest            # the hardening profile on one image
./bin/con-unit test alpine:latest --pack hygiene
./bin/con-unit rules                         # the generated rule reference
```

Engine-backed tests and the evaluation commands are listed in `justfile` and in `ONBOARDING.md`.

## Documentation

- `docs/RULES.md`: every check with its oracle, evidence, limits and standard mapping, generated from the code.
- `docs/ANALYSIS_PLAN.md`: the evaluation protocol, written before any data, with the decision rules.
- `docs/DEVIATIONS.md`: changes to the design after the first version of the plan.
- `docs/CONTRACT.md` and `docs/INTERFACE_V2.md`: the interfaces that the evaluation tools share.
- `ONBOARDING.md`: architecture and directory layout for new contributors.

## Artifact

The artifact of the paper is the bundle of the final run: the study JSON, logs, journal, adjudication file, run manifest and checksums. How it is produced and checked is described in `docs/ANALYSIS_PLAN.md`, section 14.

## License

MIT, see `LICENSE`.
