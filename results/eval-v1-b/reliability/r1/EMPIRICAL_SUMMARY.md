# Empirical Evaluation Summary: Container Images

Run started: 2026-11-16T00:14:59Z

Run finished: 2026-11-16T00:16:40Z

## Run Configuration

- ConUnit version: 0.3.0
- Commit: 2f5d90257717d3977b84ac68b8ef9af2a0876fe1
- Rule pack: cis (PACK-CONUNIT-HARDENING)
- Platform: linux/amd64
- Image source policy: auto
- Tier 3 window W: 3000 ms (a lower bound on Tier 3 latency, not a performance result)
- Engine: podman 4.9.3
- Rootless: false
- Host: linux/amd64 7.0.0-1014-aws
- Virtualization: aws-nitro-kvm
- Instance type: c6i.2xlarge
- vCPUs: 8
- Dataset SHA-256: 61d23c7e522abe10469322ca6a803eafea23dffef7552167d8cea10ee0137ea0

## Sample Flow and Attrition Accounting

- Attempted images: 10
- COMPLETED: 10
- Not completed: 0

## Resources (ConUnit process only)

These figures describe the ConUnit process. They exclude the container engine and the probe containers.

- Peak resident set size over the whole run: 22.5 MiB (a ceiling of the process, not a per-image value)
- CPU time of the ConUnit process, summed over images: 1.08 s
- CPU time of child processes (engine CLI, Syft), summed over images: 33.37 s

## Results Matrix

Counts are checks per image. Prevalence statistics are computed by the exporter from verified (PASS or FAIL) results only.

| Target Image | Status | Source | Registry Digest | Platform | Layers | Compressed | Uncompressed | Passed | Failed | Unverified | Duration | Stream | Tier 3 | Notes |
|:---|:---:|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| `index.docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a` | COMPLETED | local-store | `sha256:be2656061b53...` | `linux/amd64` | 1 | n/a | 8.0 MiB | 10 | 2 | 5 | 411ms | 4ms | 295ms | - |
| `index.docker.io/library/ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852` | COMPLETED | local-store | `sha256:fe81560990fa...` | `linux/amd64` | 1 | n/a | 74.6 MiB | 9 | 3 | 5 | 2.557s | 30ms | 294ms | - |
| `index.docker.io/library/nginx@sha256:901e593c95dc85f5a729f5765516321366ef4ac401821431d408897e95287d0a` | COMPLETED | local-store | `sha256:901e593c95dc...` | `linux/amd64` | 8 | n/a | 59.4 MiB | 11 | 5 | 1 | 11.429s | 22ms | 10.349s | - |
| `index.docker.io/library/python@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928` | COMPLETED | local-store | `sha256:65a65fc7b30b...` | `linux/amd64` | 4 | n/a | 116.8 MiB | 9 | 3 | 5 | 2.299s | 47ms | 309ms | - |
| `index.docker.io/library/node@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8` | COMPLETED | local-store | `sha256:a34ab6d7f6f4...` | `linux/amd64` | 4 | n/a | 164.0 MiB | 10 | 2 | 5 | 3.328s | 47ms | 621ms | - |
| `index.docker.io/library/golang@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18` | COMPLETED | local-store | `sha256:fa3d596898d9...` | `linux/amd64` | 5 | n/a | 241.3 MiB | 9 | 3 | 5 | 13.516s | 139ms | 1.307s | - |
| `index.docker.io/library/postgres@sha256:9ba53c7d41ea093baf5c1ba635ba5434c4f979880527d49bb7d9237d3193085b` | COMPLETED | local-store | `sha256:9ba53c7d41ea...` | `linux/amd64` | 9 | n/a | 289.7 MiB | 13 | 3 | 1 | 18.85s | 73ms | 14.687s | - |
| `index.docker.io/library/redis@sha256:7958cfbb9d152f87dadfbc89f1b0b15938f0b81ff8982feb327476f4911935c3` | COMPLETED | local-store | `sha256:7958cfbb9d15...` | `linux/amd64` | 7 | n/a | 114.1 MiB | 14 | 2 | 1 | 17.31s | 27ms | 16.236s | - |
| `index.docker.io/library/rabbitmq@sha256:4841f6384ef8313c3594cd3f2e9f40c10805f8a61c45f08a9a5d9ddea8199267` | COMPLETED | local-store | `sha256:4841f6384ef8...` | `linux/amd64` | 11 | n/a | 177.1 MiB | 13 | 3 | 1 | 16.548s | 56ms | 13.826s | - |
| `index.docker.io/library/traefik@sha256:f4bb143d1135a579b630ed491e17ec50f6f7c9c6a30585ff3d385471d2a86f5a` | COMPLETED | local-store | `sha256:f4bb143d1135...` | `linux/amd64` | 4 | n/a | 182.6 MiB | 12 | 4 | 1 | 15.106s | 40ms | 13.682s | - |
