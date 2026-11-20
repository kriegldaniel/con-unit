# ConUnit AWS evaluation pipeline

One command provisions a short-lived EC2 instance, runs the ConUnit evaluation on it, downloads a checksummed results bundle and destroys everything again. The bundle ties every number in the paper to a release tag, a dataset hash, an AMI, an engine and the host facts.

The primary configuration is rootful Podman on Ubuntu 24.04 on a `c6i.2xlarge`. That is a virtualized Nitro host and the paper must call it that. `c6i.metal` exists only for the optional RQ3 timing run.

## 1. Flow

```
operator machine                                   EC2 instance
----------------                                   ------------
pre-flight (credentials, AMI pin, tag, bundle,
            mirror check, tofu validate)
tofu apply  ------------------------------------>  user_data.sh: watchdog, lingering, smoke checks
wait for SSH, cloud-init status --wait             ready marker
host key cross-check against console output
git archive <tag> + sha256 ---- rsync -------->    incoming/ (bundle, COMMIT, tools.lock)
ssh 'bash -s' < remote_eval.sh  ---------------->  verify bundle, install Go from go.mod (sha256 checked)
                                                   install Podman packages, record versions
                                                   install the external tools from tools.lock (3 hash checks)
                                                   install registry remap, prove it with podman pull
                                                   build con-unit, export_latex, benchmark_rq3, rq1,
                                                       crosscheck, attribute_exec, reliability
                                                   stages (fixed order): eval, export, rq3, rq1, lint,
                                                       crosscheck, attribute, ablate, reliability
rsync results <---------------------------------   status.json, BENCHMARK_COMPLETE
manifest + SHA256SUMS
tofu destroy, verify nothing is left
```

Files in this directory:

- `run_eval.sh`: operator side orchestrator. Strict mode, an exit trap that always destroys.
- `remote_eval.sh`: runs on the instance, streamed over `ssh host 'bash -s'`, so there is no nested quoting.
- `user_data.sh`: minimal first boot bootstrap (OpenTofu template).
- `main.tofu`, `variables.tofu`, `outputs.tofu`, `versions.tofu`, `.terraform.lock.hcl`: infrastructure.
- `tools.lock`: pinned version, url and sha256 of dockle, hadolint, trivy and container-structure-test (section 3, "External tools").
- `amis.json`: pinned AMI per region, read by OpenTofu and by `run_eval.sh`.
- `pin_ami.sh`: the only place that looks up "newest", used to (re)pin.
- `justfile`: all entry points, `just --list`.
- `tests/`: offline tests, `just validate` runs them.

## 2. Prerequisites

Enter the dev shell: `direnv allow` in the submission root (provides `tofu`, `aws`, `jq`, `just`) or `nix develop ./eval-infra` (adds `rsync`, `git`, `curl`, `ssh`, `shellcheck`). Scripts need bash 4 or newer, which both shells provide.

Credentials: AWS only. Export `AWS_PROFILE`, or `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (plus `AWS_SESSION_TOKEN` for temporary credentials). No registry credentials are needed anywhere, see section 4. No credentials are ever written to the instance. The instance has no IAM role.

An SSH key pair: private key `~/.ssh/id_ed25519` by default (`--ssh-key` or `CONUNIT_SSH_KEY`), public key next to it. A passphrase protected key must be loaded into an ssh-agent.

The tool repository: the con-unit checkout next to the submission repo (`../con-unit`), or `--con-unit-dir`. The run evaluates a tag, default `eval-v1`.

### AWS permissions

The simplest policy for a dedicated account or role is the managed policy `AmazonEC2FullAccess`. The pipeline only touches EC2 and calls STS. The actions it uses:

- `sts:GetCallerIdentity`
- instances: `ec2:RunInstances`, `ec2:TerminateInstances`, `ec2:DescribeInstances`, `ec2:DescribeInstanceTypes`, `ec2:DescribeInstanceAttribute`, `ec2:ModifyInstanceAttribute`, `ec2:DescribeInstanceCreditSpecifications`, `ec2:GetConsoleOutput`
- images: `ec2:DescribeImages`
- key pairs: `ec2:ImportKeyPair`, `ec2:DeleteKeyPair`, `ec2:DescribeKeyPairs`
- security groups: `ec2:CreateSecurityGroup`, `ec2:DeleteSecurityGroup`, `ec2:DescribeSecurityGroups`, `ec2:DescribeSecurityGroupRules`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:AuthorizeSecurityGroupEgress`, `ec2:RevokeSecurityGroupIngress`, `ec2:RevokeSecurityGroupEgress`
- network discovery: `ec2:DescribeVpcs`, `ec2:DescribeVpcAttribute`, `ec2:DescribeSubnets`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeAvailabilityZones`, `ec2:DescribeAccountAttributes`
- volumes and tags: `ec2:DescribeVolumes`, `ec2:CreateTags`, `ec2:DeleteTags`, `ec2:DescribeTags`

If an `AccessDenied` shows up, the exit trap still destroys whatever was created. `ec2:DescribeImages` alone is enough for `just pin-ami`.

## 3. Procedure

### Once per release: pin the AMI

```
cd eval-infra
just pin-ami eu-central-1      # writes the newest Canonical Ubuntu 24.04 AMI into amis.json
git add amis.json && git commit -m "chore(eval-infra): pin Ubuntu 24.04 AMI for eu-central-1"
```

`just show-ami` prints the newest candidate next to the current pin without changing anything. Runs always use the pin, never "newest". The pre-flight verifies that the pinned AMI still exists, belongs to Canonical, is x86_64 and available.

### Canary (do this first)

The canary exercises every stage: the eval of 3 images and its export, 3 RQ3 trials with Dockle, 4 RQ1 cases, the lint pack and the cross-check on the 3 images, the attribution (study run, seeded images, truth run), the ablation, and the reliability runs on a 3 image subset of the 10 image dataset. The watchdog is 90 minutes. It is a pipeline check, not a study result, and its bundle must not be used for the paper.

The canary of the three original stages took about 4 minutes. The canary with every stage has been run on the tags `eval-v1-rc3` and `eval-v1-rc4` and took about 10 minutes end to end. The five reliability evals are expected to take the largest share: Tier 3 observes every image for W once as a baseline and once per treatment, one after another, so W of 30 s alone costs about 2.5 minutes per image for a pack with four treatments.

```
cd eval-infra
just preflight                 # optional, creates nothing in AWS
just canary
```

Until the release tag exists, either create a release candidate tag in the con-unit repo (`git tag eval-v1-rc1`) and run `just canary --tag eval-v1-rc1`, or run `just canary --allow-dirty`, which archives the working tree and marks the run tainted.

What to inspect in `results/<RUN_ID>/` after the canary:

- `run_manifest.json`: `outcome` is `complete`, `teardown.verified` is `true`.
- `host/mirror_proof_pull.log`: mentions `public.ecr.aws`, never `registry-1.docker.io`.
- `host/run_block_summary.json`: `engine_version`, `rootless`, `cgroup_version`, `ami_id` and `registry_remap` are filled (the stage `run_block_check` fails the run otherwise). `tainted` shows `false`, the tool omits it when false.
- `empirical_study.json`: 3 image records, each with a typed status, `image_source` set.
- the generated `.tex` files and the `rq3/` outputs exist.
- `journal.jsonl`, `ATTRITION_REPORT.md`.
- `status.json`: every requested stage is `ok`. Each stage has `exit_code`, and `outputs` with the number of files and the sha256 of their listing. The state `incomplete` (exit code 3) keeps partial results, `failed` with 127 means that a tool or binary was missing and nothing ran, with 66 that an input or the main output file was missing.
- `host/tool_versions.json`: the four tools with version, url, download hash, installed binary hash and version output.
- `rq1/rq1_results.json`, `lint/empirical_study.json`, `crosscheck/crosscheck.json`, `attribution/attribution.json` and `attribution/ablation.json`, `reliability/reliability.json`.
- `attribution/seeded_build/` exists only when the seeded images had to be built (see the stage list below).

### Final evaluation: run A and run B

The final evaluation is two runs of the same tag on two instances, started together in two terminals. Both run the `eval` stage on the 100 images, which also gives the run to run agreement.

```
cd eval-infra
just final-a                   # run id eval-v1-a: eval, export, rq3, rq1, lint, crosscheck
just final-b                   # run id eval-v1-b: eval, export, attribute, ablate, reliability
```

Both recipes use tag `eval-v1` and a 240 minute watchdog. The run ids are `<base>-a` and `<base>-b`, the base is `eval-v1` or the value of `FINAL_RUN_BASE`. A pilot on a release candidate tag is `FINAL_RUN_BASE=eval-v1-rc3 just final-a --tag eval-v1-rc3`, and the same for `final-b`. Extra arguments are passed on to `run_eval.sh`. Each run takes about 2 hours, which is a planning figure and not a measurement, see section 7.

`just full` keeps the three original stages (eval, export, rq3) for a single run.

### The stages

`remote_eval.sh` runs the requested stages in a fixed order, whatever the order of `--stages`. Every stage writes `stage_logs/<stage>.log`, a state and an exit code into `status.json`, and its output files are covered by `REMOTE_SHA256SUMS`. A stage starts only when the tools and binaries it needs are there, otherwise it ends `failed` with exit code 127 and nothing runs.

- `eval`: `con-unit eval` on the dataset, outputs in the results directory. Then `run_block_check`, which also requires the version of every external tool that a requested stage needs in `run.tools` of the study, equal to the pinned one.
- `export`: `export_latex`, with the audit file and `-pinned fixtures/evaluation_dataset_pinned.json` (the alpine and slim tag counts). A missing pinned file fails the stage.
- `rq3`: `benchmark_rq3`, with `-dockle dockle`. Needs dockle.
- `rq1`: `bin/rq1 -oracle fixtures/rq1/oracle.json -out-dir rq1 -conunit bin/con-unit -engine podman -keep-images -require-all`, through the engine user, with Trivy's offline environment. Needs all four tools. The images stay in the store. `-require-all` is passed for a full run only: with `--rq1-cases N` (the canary) the other cases are NOT_RUN by design and the flag would end the stage incomplete every time.
- `lint`: `con-unit eval --pack lint` over the eval dataset into `lint/`. Static, no tool.
- `crosscheck`: `bin/crosscheck -study lint/empirical_study.json -dockle dockle -out-dir crosscheck`. Needs dockle and the lint study.
- `attribute`: `bin/attribute_exec -study empirical_study.json -out-dir attribution`, then the truth run `-truth fixtures/rq1/tier3_truth.json -image-prefix localhost/conunit-rq1` into the same directory. Run B has no `rq1` stage, so when a seeded image `<prefix>/<case>:rq1` is missing the stage builds them first with `bin/rq1 -tools conunit -cases <seeded cases> -keep-images` (output in `attribution/seeded_build/`). If they are still missing, the truth run is skipped and the stage ends `incomplete` (exit code 3), never silently.
- `ablate`: `bin/attribute_exec -ablation -study empirical_study.json -out-dir attribution`. `attribute` and `ablate` share one directory, so the table and the macros of the attribution come from one place.
- `reliability`: every image of the 10 image dataset is put into the store first, then five evals into `reliability/r1`, `r2`, `r3` (W of 3 s), `w10` (10 s) and `w30` (30 s) with the pack of the run, and no image is removed between them. Then `bin/reliability -runs r1=...,r2=...,r3=... -windows w3=<r1>,w10=...,w30=... -out-dir reliability`. The windows are fixed, `--probe-window` does not change them. The exit code of each eval is in `reliability/run_exit_codes.tsv` and `status.json`.

The canary and the runs with `--rq1-cases N` use only the first N cases of the oracle (4 in the canary). In a canary the 10 image dataset is cut to the first 3 lines for `rq3` and for `reliability`.

### External tools

`tools.lock` has one line per tool, `name version url sha256`, for dockle, hadolint, trivy and container-structure-test (linux amd64, from the release pages on github.com). `run_eval.sh` checks it before anything is provisioned (a placeholder instead of a hash, a missing tool or a malformed line stop the run), ships it next to the bundle and passes its hash to the instance. The instance installs only the tools that the requested stages need, and only when all of these hold:

1. the file on the instance has the hash that the operator machine computed,
2. the download has the sha256 pinned in the file,
3. the checksum file that the release itself publishes, fetched from another path than the download (`dockle_<v>_checksums.txt`, `trivy_<v>_checksums.txt`, `<asset>.sha256` or `checksums.sha256` of hadolint, `checksums.txt` of container-structure-test), lists the same sha256 for the same file name.

The binary goes to `/usr/local/bin`. It has to run, print the pinned version, and be the one that `PATH` resolves. The result is `host/tool_versions.json` (also in `run_manifest.json`, section 6), and `status.json` carries it as `external_tools`.

Pinned at the time of writing (2026-11-15): dockle 0.4.15, hadolint 2.14.0, trivy 0.76.1, container-structure-test 1.22.1. These are the versions that the RQ1 oracle records its catalog scopes at. To change a pin, fetch the release and its checksum file, compare the hash you compute with the published one, then change version, url and sha256 together and run `just validate`. A value that cannot be verified must stay a placeholder (the word `UNVERIFIED` in place of the hash). That fails the pre-flight, the installer and the test.

Trivy is only ever run with offline settings, as environment variables of the `rq1` stage: no vulnerability database, checks bundle or Java index download, no version check, no telemetry. The Docker Hub block therefore stays in place, and the tools themselves come from github.com. With these settings Trivy 0.76.1 ran with `--network none` and fell back to its embedded checks, which it reports as an error line (`Falling back to embedded checks`) and which is expected.

The run is unattended. Follow it in the terminal, or from a second terminal:

```
ssh -F .runs/<RUN_ID>/ssh_config conunit-eval 'tail -f /opt/con-unit/results/<RUN_ID>/remote_eval.log'
```

If the SSH connection drops, the remote run continues and `run_eval.sh` re-attaches by polling `status.json`.

### Sensitivity runs and the RQ3 timing run

- `just sensitivity-rootless`: rootless Podman on the 10 image set, stages eval and export. The run id gets the suffix `-rootless`.
- `just rq3-metal`: stage rq3 only on a `c6i.metal` instance with a 120 minute watchdog.
- Any other combination: `just full --mode rootless --dataset <path> --stages eval,export` and so on. `bash run_eval.sh --help` lists everything.

### Docker Engine

Not implemented. `remote_eval.sh` installs and measures Podman only.

## 4. Registry access without Docker Hub

The dataset spells references as `index.docker.io/library/<name>@sha256:<digest>`. A digest identifies content, so the same bytes are served by the ECR Public mirror of the Docker Official Images, `public.ecr.aws/docker/library/<name>`. The instance maps one to the other with a single Podman remap, installed exactly as in `docs/CONTRACT.md` section 9:

```
[[registry]]
prefix = "docker.io/library"
location = "public.ecr.aws/docker/library"
```

There is no Docker Hub fallback entry, so a mirror failure is loud. No account or token is needed. ECR Public allows 10 pulls per second from EC2.

Three layers of assurance:

1. Pre-flight, on the operator machine: `tools/check_mirror.sh` from the tagged bundle HEAD-checks every pinned digest on the mirror at 1 request per 1.1 seconds. Any missing digest or digest mismatch aborts the run before anything is provisioned. The per-digest result is kept in `preflight/mirror_check_*.json`.
2. On the instance, before the evaluation: `podman pull --log-level=debug` of one tiny digest-pinned image (busybox, else alpine, else the first dataset line). The debug log must mention `public.ecr.aws` and must not mention `registry-1.docker.io`, otherwise the run aborts. The log is saved as `host/mirror_proof_pull.log`. The proof image is removed afterwards so every dataset image takes the same pull path.
3. By default Docker Hub is made unreachable on the instance (`/etc/hosts` entries to 0.0.0.0). If any component, including the tool's own registry reader, tried to fall back to Docker Hub, it would fail loudly instead of silently bypassing the mirror. Pass `--allow-docker-hub` to disable this. The setting is recorded in the manifest as `execution.docker_hub_blocked`.

The remap is recorded in the status file and, by the tool, in `run.registry_remap` of `empirical_study.json`.

## 5. Safety model

- The exit trap runs on success, failure, Ctrl-C and SIGTERM. It first tries a last download of results, then runs `tofu destroy` (3 attempts), then verifies. The transcript tee is shielded from the terminal's Ctrl-C so the teardown cannot die of a broken pipe.
- Teardown is verified, not assumed: the run's OpenTofu state must list no resources, and no instance, volume, security group or key pair tagged `RunId=<RUN_ID>` may exist. Otherwise the script exits with code 4 and prints the recovery command.
- Recovery after an interrupted run or expired credentials: `just destroy <RUN_ID>` (same as `./run_eval.sh --destroy-run <RUN_ID>`). Each run keeps its OpenTofu state and variables in `eval-infra/.runs/<RUN_ID>/`, which is git-ignored. `just runs` lists runs and remaining state, `just leaks` lists any con-unit instance alive in the region.
- The instance has its own watchdog, a transient systemd timer armed by `user_data.sh` (default 360 minutes, canary 90, the final recipes 240). When it fires the instance powers off. EC2 `instance_initiated_shutdown_behavior` is `terminate`, so it is terminated and its root volume deleted, not merely stopped. Disarm with `sudo systemctl stop con-unit-watchdog.timer`, only useful together with `--keep`.
- `--keep` leaves the resources running for debugging. The watchdog still terminates them.
- SSH is limited to your public address as a /32, discovered automatically (`--ssh-cidr` to override). `0.0.0.0/0` and anything wider than /16 are rejected by the script and by an OpenTofu validation.
- SSH uses a dedicated `known_hosts` per run with `StrictHostKeyChecking accept-new`. After cloud-init, the host key recorded on first contact is compared with the keys cloud-init printed to the instance console. A mismatch aborts. If the console output is not available yet, the result is recorded as `unavailable` in the manifest.
- IMDSv2 is required with hop limit 1. The root volume is encrypted. No IAM role is attached. Outbound traffic is open because the destinations sit behind CDNs.
- The bundle comes from `git archive <tag>`: the content is exactly the tagged commit, with sha256 verified on the instance. `--allow-dirty` archives the working tree instead and marks the run tainted. Tainted runs are for development only.
- Every wait is bounded: 60 SSH attempts of 10 seconds, then `cloud-init status --wait` with a 15 minute limit.

Exit codes of `run_eval.sh`: 0 complete, 1 error, 2 usage error, 3 evaluation incomplete (partial results are kept and exported), 4 teardown not verified.

## 6. Results bundle

`results/<RUN_ID>/` in the submission repository:

- `run_manifest.json`, `SHA256SUMS`, `run_eval.log` (local transcript)
- `preflight/`: `ami.json`, `git.txt`, `COMMIT`, `mirror_check_eval.json`, `mirror_check_rq3.json`, `tofu_init.log`, and for tainted runs `worktree.diff`
- from `con-unit eval`: `empirical_study.json`, `journal.jsonl`, `EMPIRICAL_SUMMARY.md`, `ATTRITION_REPORT.md`, `logs/`
- from `export_latex`: the `.tex` tables and macros
- `rq3/`: output of `benchmark_rq3`
- `rq1/`: `rq1_results.json`, `table_rq1_detection.tex` and `raw/` of the RQ1 benchmark
- `lint/`: the study of the lint pack (`empirical_study.json` and the usual eval files)
- `crosscheck/`: the Dockle cross-check (`crosscheck.json`, `discordances.csv`, the table and macros)
- `attribution/`: attribution, truth run and ablation (`attribution.json`, `attribution.csv`, `ablation.json`, table and macros), and `seeded_build/` when the seeded images were built by the stage
- `reliability/`: `r1`, `r2`, `r3`, `w10`, `w30` (one eval each), `run_exit_codes.tsv`, and the summary (`reliability.json`, table and macros)
- `host/`: `system.txt`, `uname.txt`, `lscpu.txt`, `lscpu.json`, `dpkg_versions_runtime.tsv`, `dpkg_versions_all.tsv`, `podman_info.txt`, `podman_info.json`, `podman_version.txt`, `registries_conf.txt`, `mirror_proof_pull.log`, `docker_hub_block.txt`, `versions.json`, `tool_versions.json`, `tools.lock`, `imds.json`, `build_info.txt`, `go_dist.sha256`, `run_block_summary.json`, `after_run.txt`
- `stage_logs/`: one log per stage
- `status.json`, `BENCHMARK_COMPLETE`, `REMOTE_SHA256SUMS`, `remote_eval.log`, `bundle_COMMIT.txt`

Verify a bundle with `just verify <RUN_ID>`. `SHA256SUMS` covers every file except itself and `run_eval.log`, which is a copy of the still open local transcript. `REMOTE_SHA256SUMS` was computed on the instance and is checked right after the download.

### Reading `run_manifest.json`

- `outcome`: `complete`, `incomplete` (eval exit code 3, some images did not complete), `failed`, or `aborted-before-remote-run`. A suffix `-teardown-unverified` means the resources may still exist.
- `source`: requested tag, bundle kind (`tag` or `worktree`), `commit` (the commit the binaries are stamped with), `tainted`, bundle sha256.
- `dataset`: the evaluated file with sha256 and entry count, the 10 image file (`rq3`, also read by the reliability stage, then listed again as `reliability`), whether the mirror check ran.
- `infrastructure`: region, instance type and id, AMI id, name and creation date, root volume size, watchdog minutes, host key check result.
- `execution`: engine mode, stages, pack, platform, image source policy, probe window W, number of RQ1 cases (0 means all), RQ3 iterations and warm-up, `docker_hub_blocked`, registry remap.
- `timestamps`, `exit_codes` (remote script and every stage), `teardown` (verified flag and the remaining resource counts).
- `tool_versions`: `local` (the operator tools), `remote` (from `host/versions.json`), `installed` (the content of `host/tool_versions.json`: for each external tool the pinned version, url, download hash, installed binary hash and version output, plus the hash of the lock file that the instance used) and `lock_sha256_shipped` (the hash the operator machine computed).

`BENCHMARK_COMPLETE` is written on the instance only after every requested stage has been attempted. Its content is `status.json`. Read the field `result` (`complete`, `incomplete`, `failed`), the file alone does not mean success.

## 7. Cost and time

Computed by OpenTofu from instance type, volume size and watchdog (`tofu output estimated_cost`), using us-east-1 on-demand list prices. Other regions differ, eu-central-1 is typically 10 to 15 percent higher. Treat all figures as approximate.

- `c6i.2xlarge`: about 0.34 USD per hour, plus about 0.016 USD per hour for 150 GB gp3, together about 0.36 USD per hour.
- Final evaluation, `just final-a` and `just final-b`: measured on the tag `eval-v1` (see below), run A took about 1.6 hours and run B about 1.2 hours end to end, and the two together cost about 1 USD at us-east-1 prices and about 1.2 USD in eu-central-1. The 240 minute watchdog of each final run bounds the worst case at about 1.4 USD per run, about 2.9 USD for both.
- Canary of the three original stages: measured 3 min 51 s end to end (instance up in 34 s, remote setup and build 35 s, 3 image eval 36 s, 12 RQ3 trials 50 s, teardown 42 s), so a few cents. The canary with every stage took about 10 minutes end to end on `eval-v1-rc4`. Its 90 minute watchdog bounds it at about 0.5 USD.
- `just full` (eval, export, rq3): extrapolated from the old canary at roughly 40 to 60 minutes (100 images at about 12 s each, 110 RQ3 trials at about 5 s each, 2.5 minutes of fixed cost), so well under 1 USD. The Dockle timing in rq3 adds to that.
- `c6i.metal`: about 5.44 USD per hour. A 2 hour RQ3 timing run is about 11 USD.

Measured on the pilot of the tag `eval-v1-rc4` (10 images, every stage, rootful Podman 4.9.3 on a `c6i.2xlarge`): 52 minutes end to end, 49 of them on the instance, about 0.35 USD. The stages took, in minutes, eval 2.0, export 0, rq3 15.5, rq1 9.4, lint 0.1, crosscheck 0.1, attribute 2.9, ablate 0.1 and reliability 17.8. Only eval, lint, crosscheck, attribute and ablate grow with the number of images. The other stages have a fixed size.

Measured on the final runs of the tag `eval-v1` (100 images, run A and run B in parallel on two `c6i.2xlarge` instances, 2026-11-15): run A took 91.9 minutes on the instance and 95.9 minutes end to end, run B 69.6 and 73.7 minutes. The stages of run A took, in minutes, eval 35.2, rq3 16.0, rq1 9.4, lint 15.0 and crosscheck 15.6. The stages of run B took eval 32.1, attribute 16.9, ablate 1.7 and reliability 18.3. Eval needed about 20 seconds per image, against about 12 seconds in the pilot, because the 100 images include several that are a few gigabytes large, and lint and crosscheck each need about 9 seconds per image, because they read every image once more. Attribution needed about 27 seconds per failing pair for 37 pairs. The pilot projection of about 52 minutes for run A and about 65 minutes for run B was therefore too low for run A, whose lint and crosscheck stages grow with the image sizes of the full dataset, and close to the measurement for run B.

## 8. Tests

`just validate` runs, all offline and without AWS calls: `tofu fmt -check`, `tofu validate`, a render check of `user_data.sh` through `tofu console`, `bash -n` on every script, and the test files below. `just lint` runs shellcheck over every script and test.

- `tests/test_remote_eval.sh`: argument validation (every stage, the lock hash, `--rq1-cases`), dataset helpers, the package pre-check, the registry remap, the status file and the classification of the result over the new stages.
- `tests/test_tools_install.sh`: the format of `tools.lock` (the committed file, two valid variants and fourteen variants that must fail, among them a placeholder), the layouts of the checksum files that releases publish, the version output, which stage needs which tool, and the installer against a fake release server. It covers the install of each tool and every refusal: a tampered download, a checksum file that disagrees or is missing, a lock hash that differs from the shipped one, a binary of another version, a binary that `PATH` resolves elsewhere and a failed copy.
- `tests/test_stages.sh`: each stage with fake binaries. It pins the exact commands, the fixed order, the early failure when a tool or binary is missing (exit code 127), the mapping of exit codes to `ok`, `incomplete` and `failed`, the seeded images of the attribution (present, built, still missing, no truth file), the five reliability runs, the per stage output checksum, the canary subsets and the run block check of the tool versions.
- `tests/test_run_eval.sh`: the real `run_eval.sh` against stub `aws`, `tofu`, `ssh` and `rsync`. It checks that resources are destroyed on success, incomplete results, remote failure, SSH never coming up, a failed apply, SIGTERM during the remote run and a failed destroy, plus the `--keep`, `--destroy-run`, `--allow-dirty`, mirror failure and usage error paths, the stage selection, the upload and hash check of `tools.lock`, the refusal of an unusable `tools.lock` before anything is provisioned, the manifest fields of the new stages, and that the redacted bundle passes the identifier scan.
- `tests/test_justfile.sh`: the recipes `final-a`, `final-b`, `canary` and `full` (stages, run ids, watchdog, extra arguments) and that `just validate` runs every test file.
- `tests/harness.sh`: the shared helper of the tests that call functions of `remote_eval.sh`.

The real releases were also exercised once by hand on 2026-11-15: `install_tools` ran against the real github.com downloads and checksum files of the four pinned versions, with only the version probe replaced because the binaries are Linux binaries and the machine was a Mac. That run is not part of the offline tests.

## 9. Known limits

- apt packages are not version pinned. Their exact versions are recorded in `host/dpkg_versions_*.tsv`.
- The Go tarball checksum comes from `https://go.dev/dl/?mode=json`, a different host than the tarball download, but both are Go project infrastructure.
- Syft is not installed on the instance (`run.tools` records every external tool as `absent`). The two checks that need it, SUP-01 and SUP-03, are not part of the 17 check hardening profile the run uses (the canary shows SUP-02 as the only SUP check, UNVERIFIED with `NO_TRUST_POLICY`), so they do not appear in the study. A pack that includes them would report them UNVERIFIED with reason `TOOL_UNAVAILABLE`. Syft would also read images through its own registry client, which ignores the Podman remap.
- RQ1 runs on the instance as stage `rq1`. The pre-flight mirror check covers the datasets only, not the digest-pinned base images of the RQ1 corpus. A base image that is missing on the mirror therefore shows up as a failed build in the `rq1` stage, or in the seeded image build of the `attribute` stage. The canary exercises both.
- The tools of `tools.lock` are verified against the pin and against the checksum file of their own release. Signature or provenance files that some releases publish (Trivy publishes sigstore bundles) are not verified.
- The seeded images of run B are built on the instance by the `attribute` stage, run A builds them in `rq1`. Both use the same corpus, but they are separate builds.
- Docker Engine sensitivity runs are not implemented.
- Podman 4.9.3 on Ubuntu 24.04 prints one `Error validating CNI config file /etc/cni/net.d/87-podman-bridge.conflist` warning on first use. The package ships a CNI network file while the backend is netavark (`host/podman_info.txt` shows `networkBackend: netavark`). The warning is harmless and the host is left as the package installed it.

## 10. Secrets, sharing and cleanup

What exists and where it lives:

- The SSH private key (for example `~/.ssh/conunit_eval`) stays on the operator machine. It is never copied to the instance. OpenTofu imports only the public half as a key pair named `con-unit-eval-<hex>` and deletes it at teardown. The manifest field `teardown.remaining.key_pairs` must be `0`.
- AWS credentials are the operator's session or profile. The instance has no IAM role and holds no credentials.
- `eval-infra/.runs/<RUN_ID>/` is git-ignored and holds the OpenTofu state, `run.tfvars.json` (with your SSH source address and the key path), `ssh_config` and `known_hosts`. It never belongs in a bundle or a commit.

Before anything is committed, pushed, attached to a submission or pasted into a chat:

```
cd eval-infra
just scan                                   # submission repo (what git would add, results included) with identifiers
just scan --identifiers ../results/<RUN_ID> # one bundle
just scan --repo ../../con-unit             # the tool repo, expect the documented test fixtures
```

`scan_secrets.sh` looks for private key blocks, AWS access key ids, AWS secret and session token assignments, GitHub and Slack tokens, macOS home directories and, with `--identifiers`, the AWS account id, IAM user name and public address of the current session. It prints only a label and `file:line`, never the matched text. The expected hits in the tool repo (9 at `eval-v1-rc2`) are the synthetic secrets of the unit tests and of the RQ1 defect corpus (documented AWS example values) and the podman machine fixture, whose neutral home directory `/Users/user/` still matches the home directory pattern. In a bundle of a full run, the raw scanner output of the two seeded cases `secret-in-env-defect` and `private-key-file-defect` under `rq1/raw/` holds the same synthetic values (the documented AWS example key `AKIAIOSFODNN7EXAMPLE` and random PEM bodies). The pilot bundle of `eval-v1-rc4` has 18 such hits. They are accepted. A hit anywhere else, or a value other than the documented example, is a finding.

A bundle is checksummed, so it cannot be scrubbed afterwards without breaking `SHA256SUMS`. That is why `run_eval.sh` redacts while it assembles the bundle (`redact_bundle`, before `write_checksums`). Two kinds of local files carry operator values by construction: `run_eval.log` (the transcript, which includes the OpenTofu plan and destroy output with the SSH source address, ARNs with the account id, the public key and the key path) and the files under `preflight/` (`git.txt` holds `con_unit_dir`). In the copies inside the bundle the home directory becomes `~`, the SSH source address `<operator-ip>`, the AWS account id `<aws-account-id>` and a `user@host` key comment `<key-comment>`. `REDACTION.txt` in the bundle says so and is covered by `SHA256SUMS`. Files from the instance are never modified. `preflight/worktree.diff` (tainted runs) stays byte for byte. The unredacted originals stay in `.runs/<RUN_ID>/`, and the terminal itself is not redacted, so do not paste or screenshot console output. The instance's own public address is kept, it is gone after teardown. Scan every new bundle with `just scan --identifiers ../results/<RUN_ID>` before it is committed.

Cleanup when the evaluation is finished:

```
just leaks && just runs                      # no instance, no state resources
aws ec2 describe-key-pairs --region eu-central-1 --filters Name=tag:Project,Values=con-unit   # none left
rm ~/.ssh/conunit_eval ~/.ssh/conunit_eval.pub   # the key has no passphrase, delete it instead of rotating
rm -r .runs                                  # only after the bundles are final
aws logout --profile conunit-login           # then remove the conunit and conunit-login profiles from ~/.aws/config
```

A static access key in `~/.aws/credentials` is a larger exposure than anything in this pipeline. If it is not needed any more, deactivate and delete it in IAM.
