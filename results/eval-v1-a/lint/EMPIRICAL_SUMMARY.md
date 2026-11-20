# Empirical Evaluation Summary: Container Images

Run started: 2026-11-16T00:20:36Z

Run finished: 2026-11-16T00:35:33Z

## Run Configuration

- ConUnit version: 0.3.0
- Commit: 2f5d90257717d3977b84ac68b8ef9af2a0876fe1
- Rule pack: lint (PACK-IMAGE-LINT)
- Platform: linux/amd64
- Image source policy: auto
- Tier 3 window W: 3000 ms (a lower bound on Tier 3 latency, not a performance result)
- Engine: podman 4.9.3
- Rootless: false
- Host: linux/amd64 7.0.0-1014-aws
- Virtualization: aws-nitro-kvm
- Instance type: c6i.2xlarge
- vCPUs: 8
- Dataset SHA-256: a4d670b0e2c69b21207ba5406ec12482dd8dbf9fae5789e75e46e386b8fef894

## Sample Flow and Attrition Accounting

- Attempted images: 100
- COMPLETED: 100
- Not completed: 0

## Resources (ConUnit process only)

These figures describe the ConUnit process. They exclude the container engine and the probe containers.

- Peak resident set size over the whole run: 132.4 MiB (a ceiling of the process, not a per-image value)
- CPU time of the ConUnit process, summed over images: 20.10 s
- CPU time of child processes (engine CLI, Syft), summed over images: 252.45 s

## Results Matrix

Counts are checks per image. Prevalence statistics are computed by the exporter from verified (PASS or FAIL) results only.

| Target Image | Status | Source | Registry Digest | Platform | Layers | Compressed | Uncompressed | Passed | Failed | Unverified | Duration | Stream | Tier 3 | Notes |
|:---|:---:|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| `index.docker.io/library/nginx@sha256:901e593c95dc85f5a729f5765516321366ef4ac401821431d408897e95287d0a` | COMPLETED | local-store | `sha256:901e593c95dc...` | `linux/amd64` | 8 | n/a | 59.4 MiB | 14 | 2 | 0 | 372ms | 23ms | 0s | - |
| `index.docker.io/library/memcached@sha256:084fb554292d1447bc2c68b80c2331b98834514f56c866bc21a61be3c2ee376d` | COMPLETED | local-store | `sha256:084fb554292d...` | `linux/amd64` | 6 | n/a | 12.4 MiB | 15 | 1 | 0 | 217ms | 6ms | 0s | - |
| `index.docker.io/library/busybox@sha256:7aa3d3c53cc1ed823c6a5967ebaac87700a5b0766af45ff599dbca3506c8b072` | COMPLETED | local-store | `sha256:7aa3d3c53cc1...` | `linux/amd64` | 1 | n/a | 1.2 MiB | 14 | 2 | 0 | 100ms | 1ms | 0s | - |
| `index.docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a` | COMPLETED | local-store | `sha256:be2656061b53...` | `linux/amd64` | 1 | n/a | 8.0 MiB | 14 | 2 | 0 | 115ms | 4ms | 0s | - |
| `index.docker.io/library/postgres@sha256:9ba53c7d41ea093baf5c1ba635ba5434c4f979880527d49bb7d9237d3193085b` | COMPLETED | local-store | `sha256:9ba53c7d41ea...` | `linux/amd64` | 9 | n/a | 289.7 MiB | 14 | 2 | 0 | 1.12s | 71ms | 0s | - |
| `index.docker.io/library/redis@sha256:7958cfbb9d152f87dadfbc89f1b0b15938f0b81ff8982feb327476f4911935c3` | COMPLETED | local-store | `sha256:7958cfbb9d15...` | `linux/amd64` | 7 | n/a | 114.1 MiB | 14 | 2 | 0 | 518ms | 27ms | 0s | - |
| `index.docker.io/library/ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852` | COMPLETED | local-store | `sha256:fe81560990fa...` | `linux/amd64` | 1 | n/a | 74.6 MiB | 13 | 3 | 0 | 409ms | 31ms | 0s | - |
| `index.docker.io/library/python@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928` | COMPLETED | local-store | `sha256:65a65fc7b30b...` | `linux/amd64` | 4 | n/a | 116.8 MiB | 12 | 4 | 0 | 630ms | 46ms | 0s | - |
| `index.docker.io/library/node@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8` | COMPLETED | local-store | `sha256:a34ab6d7f6f4...` | `linux/amd64` | 4 | n/a | 164.0 MiB | 13 | 3 | 0 | 697ms | 47ms | 0s | - |
| `index.docker.io/library/mysql@sha256:df90258da46f6e7ff8574ff84f17618aba0765cac749928299c69fd4e7cb8ad8` | COMPLETED | local-store | `sha256:df90258da46f...` | `linux/amd64` | 10 | n/a | 887.6 MiB | 11 | 5 | 0 | 21.662s | 341ms | 0s | - |
| `index.docker.io/library/mongo@sha256:452bdaf2127b8ff851e31410a267809b9829eded219979f2210e7c7efb85a058` | COMPLETED | local-store | `sha256:452bdaf2127b...` | `linux/amd64` | 9 | n/a | 1.0 GiB | 10 | 3 | 3 | 11.986s | 254ms | 0s | - |
| `index.docker.io/library/httpd@sha256:698a0f59374eeb59c2c3ae6385c5f346edd2c70c2b63f7b552fb3d64dbc3cf66` | COMPLETED | local-store | `sha256:698a0f59374e...` | `linux/amd64` | 7 | n/a | 63.8 MiB | 13 | 3 | 0 | 1.262s | 30ms | 0s | - |
| `index.docker.io/library/rabbitmq@sha256:4841f6384ef8313c3594cd3f2e9f40c10805f8a61c45f08a9a5d9ddea8199267` | COMPLETED | local-store | `sha256:4841f6384ef8...` | `linux/amd64` | 11 | n/a | 177.1 MiB | 13 | 3 | 0 | 824ms | 55ms | 0s | - |
| `index.docker.io/library/docker@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb` | COMPLETED | local-store | `sha256:5e6baf67325a...` | `linux/amd64` | 10 | n/a | 163.3 MiB | 14 | 2 | 0 | 1.348s | 38ms | 0s | - |
| `index.docker.io/library/traefik@sha256:f4bb143d1135a579b630ed491e17ec50f6f7c9c6a30585ff3d385471d2a86f5a` | COMPLETED | local-store | `sha256:f4bb143d1135...` | `linux/amd64` | 4 | n/a | 182.6 MiB | 14 | 2 | 0 | 691ms | 39ms | 0s | - |
| `index.docker.io/library/mariadb@sha256:4ebbcf100a3ba320766dfa0e1af008df12261301db6ef72798c7650f70794aed` | COMPLETED | local-store | `sha256:4ebbcf100a3b...` | `linux/amd64` | 8 | n/a | 325.7 MiB | 13 | 3 | 0 | 4.428s | 101ms | 0s | - |
| `index.docker.io/library/golang@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18` | COMPLETED | local-store | `sha256:fa3d596898d9...` | `linux/amd64` | 5 | n/a | 241.3 MiB | 12 | 4 | 0 | 1.404s | 138ms | 0s | - |
| `index.docker.io/library/registry@sha256:82f6ff4a7f982960c8aa51617fea3aabc485df6e55cce80d22deb1de36f1bc3c` | COMPLETED | local-store | `sha256:82f6ff4a7f98...` | `linux/amd64` | 5 | n/a | 61.7 MiB | 14 | 2 | 0 | 434ms | 15ms | 0s | - |
| `index.docker.io/library/debian@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6` | COMPLETED | local-store | `sha256:9c6e381421d0...` | `linux/amd64` | 1 | n/a | 114.6 MiB | 13 | 3 | 0 | 583ms | 40ms | 0s | - |
| `index.docker.io/library/ruby@sha256:d8cb2c0714bdaba0f318af897a01d2dbde3cfa8e62d47e99cea55feb13c0e90d` | COMPLETED | local-store | `sha256:d8cb2c0714bd...` | `linux/amd64` | 5 | n/a | 165.3 MiB | 12 | 4 | 0 | 2.957s | 63ms | 0s | - |
| `index.docker.io/library/wordpress@sha256:ad1f0968c4241a683a6ca827b2b584fb6a27aecc899641f5b2cac56ece8a8472` | COMPLETED | local-store | `sha256:ad1f0968c424...` | `linux/amd64` | 23 | n/a | 771.1 MiB | 13 | 3 | 0 | 11.027s | 243ms | 0s | - |
| `index.docker.io/library/php@sha256:951fb5b1780219b81d5daffa4cebef8e0077c537f3893d9790a5dfcd66ca334d` | COMPLETED | local-store | `sha256:951fb5b17802...` | `linux/amd64` | 11 | n/a | 102.9 MiB | 14 | 2 | 0 | 1.29s | 28ms | 0s | - |
| `index.docker.io/library/sonarqube@sha256:f95aaa9016dd4e92c7d70691167a6d96dbb5d8acffd61eba1cb4335d364a7840` | COMPLETED | local-store | `sha256:f95aaa9016dd...` | `linux/amd64` | 8 | n/a | 1.3 GiB | 14 | 2 | 0 | 13.451s | 325ms | 0s | - |
| `index.docker.io/library/haproxy@sha256:b9fe316f718d5015c5cfebd8ca019591f3e44656f61d93cb8b59a1028961e530` | COMPLETED | local-store | `sha256:b9fe316f718d...` | `linux/amd64` | 6 | n/a | 41.6 MiB | 15 | 1 | 0 | 398ms | 13ms | 0s | - |
| `index.docker.io/library/influxdb@sha256:10a1a06faa4b92ba0217506255c421ddf77f5ae8139a8b7741ac770f0f881e01` | COMPLETED | local-store | `sha256:10a1a06faa4b...` | `linux/amd64` | 6 | n/a | 401.2 MiB | 14 | 2 | 0 | 4.666s | 117ms | 0s | - |
| `index.docker.io/library/cassandra@sha256:acd754f07c73f3a166bb477354b56ce9a05690c3e5e2aaacc1aab2afddba6436` | COMPLETED | local-store | `sha256:acd754f07c73...` | `linux/amd64` | 8 | n/a | 339.0 MiB | 13 | 3 | 0 | 3.41s | 86ms | 0s | - |
| `index.docker.io/library/couchdb@sha256:907eab5b7e55ab7cfd241d39b90b2a335ea40bef82acee5a37388c08bf201dda` | COMPLETED | local-store | `sha256:907eab5b7e55...` | `linux/amd64` | 11 | n/a | 285.7 MiB | 12 | 4 | 0 | 3.982s | 86ms | 0s | - |
| `index.docker.io/library/arangodb@sha256:ae1ce5af4783e008d359daaa963559aa4e32a5bd9ea54e2304f5b3adbc88c4aa` | COMPLETED | local-store | `sha256:ae1ce5af4783...` | `linux/amd64` | 4 | n/a | 581.4 MiB | 13 | 3 | 0 | 5.767s | 124ms | 0s | - |
| `index.docker.io/library/neo4j@sha256:7dbd307cc8f35d6a061cf71659d3d8f783c3db9e8c2f5bb9d54f77921931952a` | COMPLETED | local-store | `sha256:7dbd307cc8f3...` | `linux/amd64` | 6 | n/a | 618.6 MiB | 13 | 3 | 0 | 5.386s | 148ms | 0s | - |
| `index.docker.io/library/solr@sha256:4eead47c03533079d324fa49e28a73d88b1e4d9568d0d779a0bcd58520117dfe` | COMPLETED | local-store | `sha256:4eead47c0353...` | `linux/amd64` | 11 | n/a | 700.7 MiB | 14 | 2 | 0 | 6.857s | 168ms | 0s | - |
| `index.docker.io/library/zookeeper@sha256:bbf678337a9242fcb6e49e51193855078ec515251cf11fe0bcfabae6a10e040a` | COMPLETED | local-store | `sha256:bbf678337a92...` | `linux/amd64` | 10 | n/a | 302.7 MiB | 13 | 3 | 0 | 6.615s | 101ms | 0s | - |
| `index.docker.io/library/nats@sha256:afae2fdbe2e326c65e1246cb83b9d05d319188734f3bd577ac8072daae78a10f` | COMPLETED | local-store | `sha256:afae2fdbe2e3...` | `linux/amd64` | 4 | n/a | 26.8 MiB | 14 | 2 | 0 | 632ms | 12ms | 0s | - |
| `index.docker.io/library/eclipse-mosquitto@sha256:75d6662dee52c947dc9dd9c29f1d8d7ffef78ddaf38001caa09755681e8bbc98` | COMPLETED | local-store | `sha256:75d6662dee52...` | `linux/amd64` | 3 | n/a | 24.1 MiB | 13 | 3 | 0 | 615ms | 12ms | 0s | - |
| `index.docker.io/library/telegraf@sha256:4a62bd294bf2f4c1e3781194fe7b625b7e527244eeb31afd5758227914a16229` | COMPLETED | local-store | `sha256:4a62bd294bf2...` | `linux/amd64` | 5 | n/a | 330.2 MiB | 12 | 4 | 0 | 2.267s | 66ms | 0s | - |
| `index.docker.io/library/varnish@sha256:f97e894d90bccc585e5847e766696b7785c98046c29f76007f06d2e2c3228a4e` | COMPLETED | local-store | `sha256:f97e894d90bc...` | `linux/amd64` | 6 | n/a | 331.1 MiB | 11 | 5 | 0 | 4.673s | 101ms | 0s | - |
| `index.docker.io/library/tomcat@sha256:801c473ea864cab344fcaadf22789a620acaeecd9daa85e706e06a97ebc37b94` | COMPLETED | local-store | `sha256:801c473ea864...` | `linux/amd64` | 10 | n/a | 423.4 MiB | 10 | 3 | 3 | 5.646s | 159ms | 0s | - |
| `index.docker.io/library/amazoncorretto@sha256:019e58087ba4c114c817094f70d3d522bcd13e80ce9edbba6e1c67e5700bad63` | COMPLETED | local-store | `sha256:019e58087ba4...` | `linux/amd64` | 2 | n/a | 508.0 MiB | 14 | 2 | 0 | 7.441s | 144ms | 0s | - |
| `index.docker.io/library/eclipse-temurin@sha256:e1898fd6a11fc965a994d8ace186fd3585aeb636cf8f05f47a723fcfee0b0918` | COMPLETED | local-store | `sha256:e1898fd6a11f...` | `linux/amd64` | 5 | n/a | 215.4 MiB | 14 | 2 | 0 | 2.062s | 49ms | 0s | - |
| `index.docker.io/library/gradle@sha256:e46e15353757ef9c9be0197a243653e88d25ebcd4c3c841057cf839c11fcf898` | COMPLETED | local-store | `sha256:e46e15353757...` | `linux/amd64` | 11 | n/a | 769.0 MiB | 10 | 3 | 3 | 13.452s | 257ms | 0s | - |
| `index.docker.io/library/rust@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd` | COMPLETED | local-store | `sha256:f2c004e3d2d8...` | `linux/amd64` | 2 | n/a | 868.2 MiB | 13 | 3 | 0 | 5.656s | 176ms | 0s | - |
| `index.docker.io/library/swift@sha256:53cb05862760a5270ec5cb86b8998d819b5fbe8b72ea35811f1f790a1542b51c` | COMPLETED | local-store | `sha256:53cb05862760...` | `linux/amd64` | 4 | n/a | 274.2 MiB | 9 | 4 | 3 | 3.408s | 124ms | 0s | - |
| `index.docker.io/library/dart@sha256:854f3c50b1cbd4a5a54c9fa67d4f5b6702ac49b4a26d21a80e7712a72528b215` | COMPLETED | local-store | `sha256:854f3c50b1cb...` | `linux/amd64` | 5 | n/a | 829.2 MiB | 12 | 3 | 1 | 3.769s | 177ms | 0s | - |
| `index.docker.io/library/erlang@sha256:0ac9b63db11be156be4e2834546e44aa0d7446aaffb05fedd4aea8c5a33ad998` | COMPLETED | local-store | `sha256:0ac9b63db11b...` | `linux/amd64` | 2 | n/a | 85.3 MiB | 13 | 3 | 0 | 749ms | 30ms | 0s | - |
| `index.docker.io/library/elixir@sha256:a2f0fe1bfd8a2f9cc91d913f4a12e6430e27e618720f753a514e2fff3d35f5a7` | COMPLETED | local-store | `sha256:a2f0fe1bfd8a...` | `linux/amd64` | 3 | n/a | 100.2 MiB | 13 | 3 | 0 | 969ms | 37ms | 0s | - |
| `index.docker.io/library/clojure@sha256:aa1b3f8a19462798a9662535d17173f501b3b45910aa7c3642aaddae41b096fa` | COMPLETED | local-store | `sha256:aa1b3f8a1946...` | `linux/amd64` | 9 | n/a | 323.6 MiB | 13 | 3 | 0 | 1.871s | 71ms | 0s | - |
| `index.docker.io/library/haskell@sha256:10500ef6abd41d210a74add013125065f92352b298999a9dfe296fb73deaccf7` | COMPLETED | local-store | `sha256:10500ef6abd4...` | `linux/amd64` | 5 | n/a | 4.1 GiB | 13 | 3 | 0 | 2m38.365s | 44.048s | 0s | - |
| `index.docker.io/library/julia@sha256:0002771531bbae894f2532a5ae02ea71c30685440ca3bdaea0a43d17e65571e0` | COMPLETED | local-store | `sha256:0002771531bb...` | `linux/amd64` | 4 | n/a | 1.1 GiB | 12 | 4 | 0 | 12.561s | 231ms | 0s | - |
| `index.docker.io/library/gcc@sha256:b8a42d6804296fbe7a54e17e9d60c3100d9e8dbe7ef88c748cae2ddb00d63ba2` | COMPLETED | local-store | `sha256:b8a42d680429...` | `linux/amd64` | 8 | n/a | 1.5 GiB | 13 | 3 | 0 | 28.269s | 418ms | 0s | - |
| `index.docker.io/library/perl@sha256:2b59ca705cf3234d62c33e27ed573809498e476d45c4d0904550d0daced6a215` | COMPLETED | local-store | `sha256:2b59ca705cf3...` | `linux/amd64` | 4 | n/a | 185.3 MiB | 13 | 3 | 0 | 3.926s | 75ms | 0s | - |
| `index.docker.io/library/phpmyadmin@sha256:e4b3eb5305cd42d21512bb55def2bab52625d56df927ad4ee1864a9354c84d40` | COMPLETED | local-store | `sha256:e4b3eb5305cd...` | `linux/amd64` | 21 | n/a | 548.7 MiB | 13 | 3 | 0 | 7.479s | 191ms | 0s | - |
| `index.docker.io/library/ghost@sha256:4195f6c405e40230cd10c0770425cf500c1f542a96e9f6584c11649c150e5a89` | COMPLETED | local-store | `sha256:4195f6c405e4...` | `linux/amd64` | 10 | n/a | 580.9 MiB | 12 | 4 | 0 | 43.714s | 1.431s | 0s | - |
| `index.docker.io/library/drupal@sha256:2869a0abe45b7ce2bc6d7a35fabe447d06393c3ce613964b3a4f1d9660eb0e08` | COMPLETED | local-store | `sha256:2869a0abe45b...` | `linux/amd64` | 21 | n/a | 607.4 MiB | 13 | 3 | 0 | 23.07s | 335ms | 0s | - |
| `index.docker.io/library/joomla@sha256:f534566df4df83d2f6751d3406dc624e5af5b3c8d7f2b2101bf3c2f4e47b31f0` | COMPLETED | local-store | `sha256:f534566df4df...` | `linux/amd64` | 21 | n/a | 699.8 MiB | 12 | 4 | 0 | 11.002s | 267ms | 0s | - |
| `index.docker.io/library/mediawiki@sha256:406a08c7f2cf5a9c9cb590bbe27a21b4d3cb3268b0acf327fa7dd2727ff6b0be` | COMPLETED | local-store | `sha256:406a08c7f2cf...` | `linux/amd64` | 22 | n/a | 1.0 GiB | 13 | 3 | 0 | 32.219s | 490ms | 0s | - |
| `index.docker.io/library/nextcloud@sha256:81cb09055a20142521a267cea2bc27e6a81a065871c70850d209f08803567dbc` | COMPLETED | local-store | `sha256:81cb09055a20...` | `linux/amd64` | 23 | n/a | 1.3 GiB | 12 | 4 | 0 | 9.132s | 482ms | 0s | - |
| `index.docker.io/library/redmine@sha256:bfceeae10eb8dd20debc581e5c2213f53949c0195449d8cb4567e0bd522be07e` | COMPLETED | local-store | `sha256:bfceeae10eb8...` | `linux/amd64` | 12 | n/a | 471.8 MiB | 13 | 3 | 0 | 13.247s | 200ms | 0s | - |
| `index.docker.io/library/yourls@sha256:3631239a8cc0f3911f0cdae00f5475f48a65b9f2c9f120ba137766bba28c945c` | COMPLETED | local-store | `sha256:3631239a8cc0...` | `linux/amd64` | 23 | n/a | 511.3 MiB | 12 | 4 | 0 | 7.891s | 161ms | 0s | - |
| `index.docker.io/library/xwiki@sha256:ebef890add0eda3b07bca92db5fbc6fb3e3a10b3dc1cea260a2b26abc77d1f26` | COMPLETED | local-store | `sha256:ebef890add0e...` | `linux/amd64` | 21 | n/a | 1.5 GiB | 10 | 4 | 2 | 27.788s | 479ms | 0s | - |
| `index.docker.io/library/odoo@sha256:d5e3a26baa044867c826dddc09058f10e2582706bf83c146ea04fea889720c76` | COMPLETED | local-store | `sha256:d5e3a26baa04...` | `linux/amd64` | 9 | n/a | 2.2 GiB | 11 | 5 | 0 | 1m33.415s | 7.05s | 0s | - |
| `index.docker.io/library/rethinkdb@sha256:81ab2da93f66126dbd20580c1720e723111cc9a698ddb1a930ec3bd6cc47f8a8` | COMPLETED | local-store | `sha256:81ab2da93f66...` | `linux/amd64` | 5 | n/a | 117.3 MiB | 13 | 3 | 0 | 2.333s | 41ms | 0s | - |
| `index.docker.io/library/flink@sha256:ffb97a54a2b59960360d3b362e64f86ed5cab82621025eeed1399074b42a7b17` | COMPLETED | local-store | `sha256:ffb97a54a2b5...` | `linux/amd64` | 10 | n/a | 902.7 MiB | 14 | 2 | 0 | 8.405s | 186ms | 0s | - |
| `index.docker.io/library/fluentd@sha256:d912cf85f0229673e22462e69ad223d10804dd8ed32b4eecff6cb7adb3707f8d` | COMPLETED | local-store | `sha256:d912cf85f022...` | `linux/amd64` | 9 | n/a | 168.2 MiB | 12 | 4 | 0 | 2.966s | 77ms | 0s | - |
| `index.docker.io/library/logstash@sha256:553b09a32c788ace7c204a68feb7d0a406b7d700a059a318c00c2ca72e626c30` | COMPLETED | local-store | `sha256:553b09a32c78...` | `linux/amd64` | 12 | n/a | 864.7 MiB | 14 | 2 | 0 | 19.537s | 302ms | 0s | - |
| `index.docker.io/library/elasticsearch@sha256:b7b0f24e9b5e90656ffe69804b3a48907499ab2b9cd67f02b7af3aff1b026a89` | COMPLETED | local-store | `sha256:b7b0f24e9b5e...` | `linux/amd64` | 10 | n/a | 1.5 GiB | 15 | 1 | 0 | 18.339s | 1.216s | 0s | - |
| `index.docker.io/library/kong@sha256:ad6cc0c8cca5b66b3cdab3bde7bc7ca973d4d820dd2c6651a7e3042f5428a76a` | COMPLETED | local-store | `sha256:ad6cc0c8cca5...` | `linux/amd64` | 4 | n/a | 371.6 MiB | 14 | 2 | 0 | 5.022s | 118ms | 0s | - |
| `index.docker.io/library/open-liberty@sha256:29dc1f49ed2ca1991c849bc974921ec655110995a2737256cfdfd29a334d1554` | COMPLETED | local-store | `sha256:29dc1f49ed2c...` | `linux/amd64` | 12 | n/a | 722.2 MiB | 13 | 3 | 0 | 11.127s | 206ms | 0s | - |
| `index.docker.io/library/ibm-semeru-runtimes@sha256:0601f9cd0e44ef93ddffef599b535d773475156f27bdcb0a2a7b6d4353baeed7` | COMPLETED | local-store | `sha256:0601f9cd0e44...` | `linux/amd64` | 4 | n/a | 352.7 MiB | 13 | 3 | 0 | 3.536s | 92ms | 0s | - |
| `index.docker.io/library/sapmachine@sha256:8c3afc896691208abee94e8db71cb972ed34a5c5b417610102261055b95d38a5` | COMPLETED | local-store | `sha256:8c3afc896691...` | `linux/amd64` | 2 | n/a | 242.1 MiB | 13 | 3 | 0 | 1.804s | 63ms | 0s | - |
| `index.docker.io/library/oraclelinux@sha256:9225108d00fb6611ebc4a5eced166f27d9dcfeaa539fb127be79425f0da5e745` | COMPLETED | local-store | `sha256:9225108d00fb...` | `linux/amd64` | 1 | n/a | 239.8 MiB | 12 | 3 | 1 | 5.915s | 98ms | 0s | - |
| `index.docker.io/library/fedora@sha256:15da97ed9aa94dd3d92c3925eb89520f6c80e07ea7ee24cba848d1f8b6912b3e` | COMPLETED | local-store | `sha256:15da97ed9aa9...` | `linux/amd64` | 1 | n/a | 176.9 MiB | 13 | 3 | 0 | 3.784s | 78ms | 0s | - |
| `index.docker.io/library/amazonlinux@sha256:c04a1012acc483977f61f7f91c28624a39a621e56a59781319a75dec528be9b6` | COMPLETED | local-store | `sha256:c04a1012acc4...` | `linux/amd64` | 1 | n/a | 143.2 MiB | 14 | 2 | 0 | 4.445s | 71ms | 0s | - |
| `index.docker.io/library/bash@sha256:589adbc588d8ef3c1ec3c68333faf4baf5dccb65d3cb50f6cf3d78cad2d6e1b0` | COMPLETED | local-store | `sha256:589adbc588d8...` | `linux/amd64` | 3 | n/a | 14.9 MiB | 14 | 2 | 0 | 273ms | 6ms | 0s | - |
| `index.docker.io/library/pypy@sha256:410aad485440d238a596fd5f847a99d3f7c11be895ce25c02b336f5c5d1733bb` | COMPLETED | local-store | `sha256:410aad485440...` | `linux/amd64` | 3 | n/a | 196.9 MiB | 13 | 3 | 0 | 2.797s | 63ms | 0s | - |
| `index.docker.io/library/composer@sha256:8de2184c6de224f4689e8f80ed5f5edaf0030b6b8b7839a22a2bcb6722ac87d0` | COMPLETED | local-store | `sha256:8de2184c6de2...` | `linux/amd64` | 14 | n/a | 214.7 MiB | 14 | 2 | 0 | 3.754s | 64ms | 0s | - |
| `index.docker.io/library/ros@sha256:00b8d47a6e6384a2834e3d01fa87ae767876543baa574f2d64a75c04ea33c698` | COMPLETED | local-store | `sha256:00b8d47a6e63...` | `linux/amd64` | 10 | n/a | 848.0 MiB | 13 | 3 | 0 | 26.442s | 358ms | 0s | - |
| `index.docker.io/library/storm@sha256:3f8c17e6ce43ac9ca6106458eb060ecf3096ba22422c4a04687b98e89cb68244` | COMPLETED | local-store | `sha256:3f8c17e6ce43...` | `linux/amd64` | 11 | n/a | 702.4 MiB | 10 | 3 | 3 | 10.216s | 211ms | 0s | - |
| `index.docker.io/library/spiped@sha256:7acba2c58083cf5246e055818bd95932bb6a26851e0123543a3c4b9681a07061` | COMPLETED | local-store | `sha256:7acba2c58083...` | `linux/amd64` | 6 | n/a | 8.3 MiB | 14 | 2 | 0 | 174ms | 4ms | 0s | - |
| `index.docker.io/library/irssi@sha256:62fbc3514f8ef0bf587137800856ee4dffbfaddf6ca8402501698a6491e3205d` | COMPLETED | local-store | `sha256:62fbc3514f8e...` | `linux/amd64` | 5 | n/a | 62.5 MiB | 15 | 1 | 0 | 1.892s | 29ms | 0s | - |
| `index.docker.io/library/rakudo-star@sha256:0bc7542202ea3d9362ce15d90a601928f02b7657630fd131ad9d9847687b65b5` | COMPLETED | local-store | `sha256:0bc7542202ea...` | `linux/amd64` | 3 | n/a | 174.9 MiB | 13 | 3 | 0 | 2.895s | 53ms | 0s | - |
| `index.docker.io/library/mageia@sha256:d7e96eb4e2f3ac6b7bdf0caecf673836323ae409b304f195a98d22ab126217d9` | COMPLETED | local-store | `sha256:d7e96eb4e2f3...` | `linux/amd64` | 1 | n/a | 326.4 MiB | 12 | 4 | 0 | 8.011s | 118ms | 0s | - |
| `index.docker.io/library/caddy@sha256:e70b164da81ef698b3ad19af799ea6086ce6d9e48ed4079eb9fe26f6fbf14ee5` | COMPLETED | local-store | `sha256:e70b164da81e...` | `linux/amd64` | 5 | n/a | 63.3 MiB | 14 | 2 | 0 | 636ms | 16ms | 0s | - |
| `index.docker.io/library/adminer@sha256:400af848ac3f57938abde4867677df1b195674d232c8896a27d111d04b9c088c` | COMPLETED | local-store | `sha256:400af848ac3f...` | `linux/amd64` | 17 | n/a | 110.8 MiB | 15 | 1 | 0 | 1.498s | 33ms | 0s | - |
| `index.docker.io/library/orientdb@sha256:26ddb8e116bf52c78b88db841295b576a1f627f995d024c5f9e5187d2dc40faa` | COMPLETED | local-store | `sha256:26ddb8e116bf...` | `linux/amd64` | 9 | n/a | 392.5 MiB | 10 | 3 | 3 | 3.99s | 149ms | 0s | - |
| `index.docker.io/library/swipl@sha256:2723fefd35116f92f68da22a487b1b01b584ac0b4b81fcd971c7ab2222f5d3e7` | COMPLETED | local-store | `sha256:2723fefd3511...` | `linux/amd64` | 3 | n/a | 265.6 MiB | 13 | 3 | 0 | 7.235s | 128ms | 0s | - |
| `index.docker.io/library/websphere-liberty@sha256:33db03751a2be1333b6b32d754bbefd3391a9b8013248c18847d49a03e807af8` | COMPLETED | local-store | `sha256:33db03751a2b...` | `linux/amd64` | 15 | n/a | 795.3 MiB | 13 | 3 | 0 | 14.927s | 265ms | 0s | - |
| `index.docker.io/library/lightstreamer@sha256:bb5f3f3f9585bb282acbe708235ede0d0a0990524d1383a5c3b2203a558b21f9` | COMPLETED | local-store | `sha256:bb5f3f3f9585...` | `linux/amd64` | 9 | n/a | 478.0 MiB | 11 | 2 | 3 | 5.796s | 165ms | 0s | - |
| `index.docker.io/library/convertigo@sha256:016dcebecb1e1b2b4233f32e12a9e46a748448848f5cee1daee16853114538a0` | COMPLETED | local-store | `sha256:016dcebecb1e...` | `linux/amd64` | 18 | n/a | 619.8 MiB | 12 | 4 | 0 | 6.342s | 168ms | 0s | - |
| `index.docker.io/library/buildpack-deps@sha256:890e8b5c0040e1deff5cc7dc7b4414e67069f79e3301afc4ec5bd49d64ef13e5` | COMPLETED | local-store | `sha256:890e8b5c0040...` | `linux/amd64` | 4 | n/a | 755.2 MiB | 12 | 4 | 0 | 13.913s | 233ms | 0s | - |
| `index.docker.io/library/clickhouse@sha256:07b744792d5b54da40ff7c5f18a9fcca929fd85f6cc317259dc5beb9dda1f90b` | COMPLETED | local-store | `sha256:07b744792d5b...` | `linux/amd64` | 8 | n/a | 861.9 MiB | 13 | 3 | 0 | 8.69s | 184ms | 0s | - |
| `index.docker.io/library/almalinux@sha256:838c2fafefb1a8a0d7f8cdbc3b0551c2a2b1eb0cd87aad6d62aecadb18311f1b` | COMPLETED | local-store | `sha256:838c2fafefb1...` | `linux/amd64` | 1 | n/a | 179.0 MiB | 13 | 3 | 0 | 4.581s | 80ms | 0s | - |
| `index.docker.io/library/neurodebian@sha256:4521313bfbf4b0dae3acd4e90b8fc5eb547d7df6b733dcfd89de1be8693e861b` | COMPLETED | local-store | `sha256:4521313bfbf4...` | `linux/amd64` | 5 | n/a | 137.1 MiB | 13 | 3 | 0 | 1.143s | 48ms | 0s | - |
| `index.docker.io/library/hitch@sha256:91a93a77157131d0f9d09dc7aea80f565eb1a40fdf537014f5bc4b9fc741ce97` | COMPLETED | local-store | `sha256:91a93a771571...` | `linux/amd64` | 4 | n/a | 81.5 MiB | 12 | 4 | 0 | 2.853s | 32ms | 0s | - |
| `index.docker.io/library/eggdrop@sha256:2028d25c44a8fa7dbbfee1e1c9db809c5ba23eaa6516fbe84eb86c44886e1e04` | COMPLETED | local-store | `sha256:2028d25c44a8...` | `linux/amd64` | 7 | n/a | 30.4 MiB | 14 | 2 | 0 | 1.219s | 18ms | 0s | - |
| `index.docker.io/library/znc@sha256:472ffdd9e52f45e0fde51db668c513d594a17679ff4ef59973aee1f60d2450e7` | COMPLETED | local-store | `sha256:472ffdd9e52f...` | `linux/amd64` | 6 | n/a | 501.7 MiB | 12 | 4 | 0 | 10.385s | 149ms | 0s | - |
| `index.docker.io/library/rockylinux@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6` | COMPLETED | local-store | `sha256:d7be1c094cc5...` | `linux/amd64` | 1 | n/a | 167.4 MiB | 13 | 3 | 0 | 5.169s | 73ms | 0s | - |
| `index.docker.io/library/photon@sha256:3d7e9a35fd55277a056d9e1c54841e6b862a8df7e0caa56fa9c0453969f5329d` | COMPLETED | local-store | `sha256:3d7e9a35fd55...` | `linux/amd64` | 1 | n/a | 46.6 MiB | 12 | 3 | 1 | 723ms | 15ms | 0s | - |
| `index.docker.io/library/krakend@sha256:9f61092f8c627bb4d536e3977332ae4712113d603720b856d9951366bbf9b3ef` | COMPLETED | local-store | `sha256:9f61092f8c62...` | `linux/amd64` | 5 | n/a | 105.7 MiB | 14 | 2 | 0 | 1.017s | 26ms | 0s | - |
| `index.docker.io/library/groovy@sha256:fa81cdb39e5418c234ee7c85c251274be021bec9fb439e374af4f0663b106a53` | COMPLETED | local-store | `sha256:fa81cdb39e54...` | `linux/amd64` | 10 | n/a | 481.1 MiB | 14 | 2 | 0 | 4.699s | 118ms | 0s | - |
| `index.docker.io/library/haxe@sha256:64b8dbc020d84ad1e519f80c382619fb6dadeb2e2b01220c83c409a8648fa010` | COMPLETED | local-store | `sha256:64b8dbc020d8...` | `linux/amd64` | 6 | n/a | 410.9 MiB | 13 | 3 | 0 | 9.493s | 158ms | 0s | - |
| `index.docker.io/library/maven@sha256:308cba8b638ed7e4658cea3f8399066219466211c805f6d5728c3c9c7614661b` | COMPLETED | local-store | `sha256:308cba8b638e...` | `linux/amd64` | 9 | n/a | 364.7 MiB | 14 | 2 | 0 | 3.547s | 79ms | 0s | - |
