ConUnit evaluation, tag eval-v1
===============================

Contents
  results/eval-v1-a          Run A. Stages: eval, export, rq3, rq1, lint, crosscheck.
  results/eval-v1-b          Run B. Stages: eval, export, attribute, ablate, reliability.
  results/eval-v1-agreement  Run-to-run agreement of A and B (output of tools/agreement).
  eval-infra/                The AWS pipeline: OpenTofu files, run scripts, pinned AMI and tool
                             versions, offline tests (the committed files only).
  supplement.pdf             Every generated table and figure of the paper, landscape.
  MANIFEST.sha256            SHA-256 of every file in this archive except itself.

Tool and commit
  Source:  https://github.com/kriegldaniel/con-unit  (tag eval-v1)
  Commit:  2f5d90257717d3977b84ac68b8ef9af2a0876fe1  (a single commit, no history)
  Both runs were built from this tag with bundle kind "tag", are not tainted, and
  finished with result "complete" and exit code 0 (see run_manifest.json and status.json).

Setup of both runs
  One AWS instance per run, type c6i.2xlarge, platform linux/amd64, rootful Podman,
  Tier 3 window 3 s, hardening profile ("cis" pack). Docker Hub was blocked on the instance.
  Digest-pinned images were fetched through the registry remap
  docker.io/library -> public.ecr.aws/docker/library. The sample is 108 candidates,
  of which 100 images completed.

Reproduce the runs
  eval-infra/ is the pipeline as committed in the paper repository (tree
  7d6721589bec5fad1cf6a9d6a3bafb150e7e3c76). It provisions one short-lived EC2 instance,
  runs the evaluation, downloads a checksummed bundle and destroys everything again.
  The final runs were started with "just final-a" and "just final-b" on tag eval-v1.
  eval-infra/README.md gives the prerequisites, the AWS permissions, the stages and the
  safety model. You need an AWS account, an SSH key pair, and a clone of the tool
  repository at tag eval-v1 (default location ../con-unit). Enter the shell with
  "nix develop ./eval-infra". The scripts and OpenTofu files are unchanged since the runs:
  the only later commit to eval-infra edited its README to record the measured times.

Where to look first
  results/eval-v1-a/EMPIRICAL_SUMMARY.md and empirical_study.json   per-image results (run A)
  results/eval-v1-a/crosscheck/                                    Dockle cross-check and discordances
  results/eval-v1-a/rq1/                                           detection matrix, seeded corpus
  results/eval-v1-a/rq3/                                           cost measurements
  results/eval-v1-b/attribution/                                   Tier 3 attribution and ablation
  results/eval-v1-b/reliability/                                   repeats of the ten-image subset
  results/eval-v1-agreement/                                       agreement between the runs

Verify the files
  cd results/eval-v1-a && shasum -a 256 -c SHA256SUMS
  cd results/eval-v1-b && shasum -a 256 -c SHA256SUMS
  SHA256SUMS covers the whole bundle. REMOTE_SHA256SUMS covers the files that were
  written on the instance.

Notes
  Redaction. The logs written on the operator machine had three kinds of values replaced
  before the checksums were computed: home directory, SSH source address, AWS account id.
  See REDACTION.txt in each run folder. The addresses and resource ids that remain in
  run_eval.log belong to instances that were terminated after the runs.
  Agreement bundle. It has no checksum file of its own. The only change to it is that
  the local home directory in agreement.json was replaced by "~".
  Seeded credentials. results/eval-v1-a/rq1/raw/secret-in-env-defect and
  results/eval-v1-a/rq1/raw/private-key-file-defect are test fixtures of the seeded
  corpus and hold fake credentials on purpose. Secret scanners may report them.
  eval-infra. Only the committed files are included. The git-ignored folders .runs (state,
  logs and addresses of every run), .terraform and .direnv are left out on purpose.
  Not included. The canary and pilot runs and the paper itself.
