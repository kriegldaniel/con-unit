# ConUnit replication package, tag eval-v1

This branch holds the replication package of the evaluation. It shares no history with `main` and is not part of the tool source.

- Tool source: branch `main`, tag `eval-v1` (commit `2f5d90257717d3977b84ac68b8ef9af2a0876fe1`).
- Start with `README.txt`: contents, setup of both runs, how to reproduce them, how to verify the files.
- Verify everything: `shasum -a 256 -c MANIFEST.sha256` in this directory, and `shasum -a 256 -c SHA256SUMS` in each run folder under `results/`.
- `README.md` (this file) is the only file that is not covered by `MANIFEST.sha256`.
- `results/eval-v1-a/rq1/raw/secret-in-env-defect` and `results/eval-v1-a/rq1/raw/private-key-file-defect` are test fixtures of the seeded corpus. They hold fake credentials on purpose, and secret scanners may report them.
