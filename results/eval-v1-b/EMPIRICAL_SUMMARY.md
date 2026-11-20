# Empirical Evaluation Summary: Container Images

Run started: 2026-11-15T23:24:18Z

Run finished: 2026-11-15T23:56:23Z

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
- Dataset SHA-256: a4d670b0e2c69b21207ba5406ec12482dd8dbf9fae5789e75e46e386b8fef894

## Sample Flow and Attrition Accounting

- Attempted images: 100
- COMPLETED: 100
- Not completed: 0

## Resources (ConUnit process only)

These figures describe the ConUnit process. They exclude the container engine and the probe containers.

- Peak resident set size over the whole run: 136.0 MiB (a ceiling of the process, not a per-image value)
- CPU time of the ConUnit process, summed over images: 22.98 s
- CPU time of child processes (engine CLI, Syft), summed over images: 1159.25 s

## Results Matrix

Counts are checks per image. Prevalence statistics are computed by the exporter from verified (PASS or FAIL) results only.

| Target Image | Status | Source | Registry Digest | Platform | Layers | Compressed | Uncompressed | Passed | Failed | Unverified | Duration | Stream | Tier 3 | Notes |
|:---|:---:|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| `index.docker.io/library/nginx@sha256:901e593c95dc85f5a729f5765516321366ef4ac401821431d408897e95287d0a` | COMPLETED | local-store | `sha256:901e593c95dc...` | `linux/amd64` | 8 | n/a | 59.4 MiB | 11 | 5 | 1 | 16.297s | 23ms | 13.734s | - |
| `index.docker.io/library/memcached@sha256:084fb554292d1447bc2c68b80c2331b98834514f56c866bc21a61be3c2ee376d` | COMPLETED | local-store | `sha256:084fb554292d...` | `linux/amd64` | 6 | n/a | 12.4 MiB | 15 | 1 | 1 | 17.667s | 6ms | 15.956s | - |
| `index.docker.io/library/busybox@sha256:7aa3d3c53cc1ed823c6a5967ebaac87700a5b0766af45ff599dbca3506c8b072` | COMPLETED | local-store | `sha256:7aa3d3c53cc1...` | `linux/amd64` | 1 | n/a | 1.2 MiB | 10 | 2 | 5 | 1.588s | 1ms | 255ms | - |
| `index.docker.io/library/alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a` | COMPLETED | local-store | `sha256:be2656061b53...` | `linux/amd64` | 1 | n/a | 8.0 MiB | 10 | 2 | 5 | 1.643s | 3ms | 252ms | - |
| `index.docker.io/library/postgres@sha256:9ba53c7d41ea093baf5c1ba635ba5434c4f979880527d49bb7d9237d3193085b` | COMPLETED | local-store | `sha256:9ba53c7d41ea...` | `linux/amd64` | 9 | n/a | 289.7 MiB | 13 | 3 | 1 | 22.879s | 70ms | 16.776s | - |
| `index.docker.io/library/redis@sha256:7958cfbb9d152f87dadfbc89f1b0b15938f0b81ff8982feb327476f4911935c3` | COMPLETED | local-store | `sha256:7958cfbb9d15...` | `linux/amd64` | 7 | n/a | 114.1 MiB | 14 | 2 | 1 | 19.977s | 26ms | 16.822s | - |
| `index.docker.io/library/ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852` | COMPLETED | local-store | `sha256:fe81560990fa...` | `linux/amd64` | 1 | n/a | 74.6 MiB | 9 | 3 | 5 | 3.091s | 29ms | 515ms | - |
| `index.docker.io/library/python@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928` | COMPLETED | local-store | `sha256:65a65fc7b30b...` | `linux/amd64` | 4 | n/a | 116.8 MiB | 9 | 3 | 5 | 4.382s | 45ms | 1.278s | - |
| `index.docker.io/library/node@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8` | COMPLETED | local-store | `sha256:a34ab6d7f6f4...` | `linux/amd64` | 4 | n/a | 164.0 MiB | 10 | 2 | 5 | 5.599s | 46ms | 1.912s | - |
| `index.docker.io/library/mysql@sha256:df90258da46f6e7ff8574ff84f17618aba0765cac749928299c69fd4e7cb8ad8` | COMPLETED | local-store | `sha256:df90258da46f...` | `linux/amd64` | 10 | n/a | 887.6 MiB | 11 | 5 | 1 | 34.422s | 307ms | 23.128s | - |
| `index.docker.io/library/mongo@sha256:452bdaf2127b8ff851e31410a267809b9829eded219979f2210e7c7efb85a058` | COMPLETED | local-store | `sha256:452bdaf2127b...` | `linux/amd64` | 9 | n/a | 1.0 GiB | 11 | 5 | 1 | 40.913s | 248ms | 22.804s | - |
| `index.docker.io/library/httpd@sha256:698a0f59374eeb59c2c3ae6385c5f346edd2c70c2b63f7b552fb3d64dbc3cf66` | COMPLETED | local-store | `sha256:698a0f59374e...` | `linux/amd64` | 7 | n/a | 63.8 MiB | 10 | 6 | 1 | 12.586s | 30ms | 10.256s | - |
| `index.docker.io/library/rabbitmq@sha256:4841f6384ef8313c3594cd3f2e9f40c10805f8a61c45f08a9a5d9ddea8199267` | COMPLETED | local-store | `sha256:4841f6384ef8...` | `linux/amd64` | 11 | n/a | 177.1 MiB | 13 | 3 | 1 | 19.073s | 54ms | 15.013s | - |
| `index.docker.io/library/docker@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb` | COMPLETED | local-store | `sha256:5e6baf67325a...` | `linux/amd64` | 10 | n/a | 163.3 MiB | 10 | 2 | 5 | 5.078s | 35ms | 1.81s | - |
| `index.docker.io/library/traefik@sha256:f4bb143d1135a579b630ed491e17ec50f6f7c9c6a30585ff3d385471d2a86f5a` | COMPLETED | local-store | `sha256:f4bb143d1135...` | `linux/amd64` | 4 | n/a | 182.6 MiB | 12 | 4 | 1 | 18.374s | 37ms | 14.93s | - |
| `index.docker.io/library/mariadb@sha256:4ebbcf100a3ba320766dfa0e1af008df12261301db6ef72798c7650f70794aed` | COMPLETED | local-store | `sha256:4ebbcf100a3b...` | `linux/amd64` | 8 | n/a | 325.7 MiB | 12 | 4 | 1 | 23.048s | 97ms | 17.823s | - |
| `index.docker.io/library/golang@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18` | COMPLETED | local-store | `sha256:fa3d596898d9...` | `linux/amd64` | 5 | n/a | 241.3 MiB | 9 | 3 | 5 | 9.005s | 134ms | 3.632s | - |
| `index.docker.io/library/registry@sha256:82f6ff4a7f982960c8aa51617fea3aabc485df6e55cce80d22deb1de36f1bc3c` | COMPLETED | local-store | `sha256:82f6ff4a7f98...` | `linux/amd64` | 5 | n/a | 61.7 MiB | 14 | 2 | 1 | 18.396s | 15ms | 16.196s | - |
| `index.docker.io/library/debian@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6` | COMPLETED | local-store | `sha256:9c6e381421d0...` | `linux/amd64` | 1 | n/a | 114.6 MiB | 9 | 3 | 5 | 4.509s | 38ms | 1.228s | - |
| `index.docker.io/library/ruby@sha256:d8cb2c0714bdaba0f318af897a01d2dbde3cfa8e62d47e99cea55feb13c0e90d` | COMPLETED | local-store | `sha256:d8cb2c0714bd...` | `linux/amd64` | 5 | n/a | 165.3 MiB | 9 | 3 | 5 | 4.738s | 61ms | 1.565s | - |
| `index.docker.io/library/wordpress@sha256:ad1f0968c4241a683a6ca827b2b584fb6a27aecc899641f5b2cac56ece8a8472` | COMPLETED | local-store | `sha256:ad1f0968c424...` | `linux/amd64` | 23 | n/a | 771.1 MiB | 11 | 5 | 1 | 33.908s | 239ms | 22.396s | - |
| `index.docker.io/library/php@sha256:951fb5b1780219b81d5daffa4cebef8e0077c537f3893d9790a5dfcd66ca334d` | COMPLETED | local-store | `sha256:951fb5b17802...` | `linux/amd64` | 11 | n/a | 102.9 MiB | 14 | 2 | 1 | 19.461s | 28ms | 16.798s | - |
| `index.docker.io/library/sonarqube@sha256:f95aaa9016dd4e92c7d70691167a6d96dbb5d8acffd61eba1cb4335d364a7840` | COMPLETED | local-store | `sha256:f95aaa9016dd...` | `linux/amd64` | 8 | n/a | 1.3 GiB | 13 | 3 | 1 | 46.798s | 266ms | 24.278s | - |
| `index.docker.io/library/haproxy@sha256:b9fe316f718d5015c5cfebd8ca019591f3e44656f61d93cb8b59a1028961e530` | COMPLETED | local-store | `sha256:b9fe316f718d...` | `linux/amd64` | 6 | n/a | 41.6 MiB | 11 | 1 | 5 | 2.469s | 13ms | 265ms | - |
| `index.docker.io/library/influxdb@sha256:10a1a06faa4b92ba0217506255c421ddf77f5ae8139a8b7741ac770f0f881e01` | COMPLETED | local-store | `sha256:10a1a06faa4b...` | `linux/amd64` | 6 | n/a | 401.2 MiB | 10 | 2 | 5 | 11.815s | 113ms | 5.272s | - |
| `index.docker.io/library/cassandra@sha256:acd754f07c73f3a166bb477354b56ce9a05690c3e5e2aaacc1aab2afddba6436` | COMPLETED | local-store | `sha256:acd754f07c73...` | `linux/amd64` | 8 | n/a | 339.0 MiB | 8 | 4 | 5 | 9.813s | 83ms | 5.031s | - |
| `index.docker.io/library/couchdb@sha256:907eab5b7e55ab7cfd241d39b90b2a335ea40bef82acee5a37388c08bf201dda` | COMPLETED | local-store | `sha256:907eab5b7e55...` | `linux/amd64` | 11 | n/a | 285.7 MiB | 9 | 3 | 5 | 10.624s | 85ms | 3.416s | - |
| `index.docker.io/library/arangodb@sha256:ae1ce5af4783e008d359daaa963559aa4e32a5bd9ea54e2304f5b3adbc88c4aa` | COMPLETED | local-store | `sha256:ae1ce5af4783...` | `linux/amd64` | 4 | n/a | 581.4 MiB | 13 | 3 | 1 | 30.861s | 120ms | 20.449s | - |
| `index.docker.io/library/neo4j@sha256:7dbd307cc8f35d6a061cf71659d3d8f783c3db9e8c2f5bb9d54f77921931952a` | COMPLETED | local-store | `sha256:7dbd307cc8f3...` | `linux/amd64` | 6 | n/a | 618.6 MiB | 10 | 6 | 1 | 26.227s | 141ms | 17.733s | - |
| `index.docker.io/library/solr@sha256:4eead47c03533079d324fa49e28a73d88b1e4d9568d0d779a0bcd58520117dfe` | COMPLETED | local-store | `sha256:4eead47c0353...` | `linux/amd64` | 11 | n/a | 700.7 MiB | 13 | 3 | 1 | 30.217s | 163ms | 21.167s | - |
| `index.docker.io/library/zookeeper@sha256:bbf678337a9242fcb6e49e51193855078ec515251cf11fe0bcfabae6a10e040a` | COMPLETED | local-store | `sha256:bbf678337a92...` | `linux/amd64` | 10 | n/a | 302.7 MiB | 11 | 5 | 1 | 19.643s | 100ms | 14.489s | - |
| `index.docker.io/library/nats@sha256:afae2fdbe2e326c65e1246cb83b9d05d319188734f3bd577ac8072daae78a10f` | COMPLETED | local-store | `sha256:afae2fdbe2e3...` | `linux/amd64` | 4 | n/a | 26.8 MiB | 14 | 2 | 1 | 18.334s | 13ms | 16.175s | - |
| `index.docker.io/library/eclipse-mosquitto@sha256:75d6662dee52c947dc9dd9c29f1d8d7ffef78ddaf38001caa09755681e8bbc98` | COMPLETED | local-store | `sha256:75d6662dee52...` | `linux/amd64` | 3 | n/a | 24.1 MiB | 13 | 3 | 1 | 15.221s | 13ms | 13.353s | - |
| `index.docker.io/library/telegraf@sha256:4a62bd294bf2f4c1e3781194fe7b625b7e527244eeb31afd5758227914a16229` | COMPLETED | local-store | `sha256:4a62bd294bf2...` | `linux/amd64` | 5 | n/a | 330.2 MiB | 9 | 3 | 5 | 12.436s | 64ms | 6.935s | - |
| `index.docker.io/library/varnish@sha256:f97e894d90bccc585e5847e766696b7785c98046c29f76007f06d2e2c3228a4e` | COMPLETED | local-store | `sha256:f97e894d90bc...` | `linux/amd64` | 6 | n/a | 331.1 MiB | 8 | 4 | 5 | 10.156s | 98ms | 4.135s | - |
| `index.docker.io/library/tomcat@sha256:801c473ea864cab344fcaadf22789a620acaeecd9daa85e706e06a97ebc37b94` | COMPLETED | local-store | `sha256:801c473ea864...` | `linux/amd64` | 10 | n/a | 423.4 MiB | 13 | 3 | 1 | 28.805s | 159ms | 22.169s | - |
| `index.docker.io/library/amazoncorretto@sha256:019e58087ba4c114c817094f70d3d522bcd13e80ce9edbba6e1c67e5700bad63` | COMPLETED | local-store | `sha256:019e58087ba4...` | `linux/amd64` | 2 | n/a | 508.0 MiB | 10 | 2 | 5 | 15.115s | 138ms | 7.653s | - |
| `index.docker.io/library/eclipse-temurin@sha256:e1898fd6a11fc965a994d8ace186fd3585aeb636cf8f05f47a723fcfee0b0918` | COMPLETED | local-store | `sha256:e1898fd6a11f...` | `linux/amd64` | 5 | n/a | 215.4 MiB | 10 | 2 | 5 | 6.814s | 47ms | 2.659s | - |
| `index.docker.io/library/gradle@sha256:e46e15353757ef9c9be0197a243653e88d25ebcd4c3c841057cf839c11fcf898` | COMPLETED | local-store | `sha256:e46e15353757...` | `linux/amd64` | 11 | n/a | 769.0 MiB | 11 | 5 | 1 | 34.39s | 253ms | 21.354s | - |
| `index.docker.io/library/rust@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd` | COMPLETED | local-store | `sha256:f2c004e3d2d8...` | `linux/amd64` | 2 | n/a | 868.2 MiB | 8 | 4 | 5 | 24.347s | 174ms | 10.632s | - |
| `index.docker.io/library/swift@sha256:53cb05862760a5270ec5cb86b8998d819b5fbe8b72ea35811f1f790a1542b51c` | COMPLETED | local-store | `sha256:53cb05862760...` | `linux/amd64` | 4 | n/a | 274.2 MiB | 9 | 3 | 5 | 7.228s | 124ms | 3.026s | - |
| `index.docker.io/library/dart@sha256:854f3c50b1cbd4a5a54c9fa67d4f5b6702ac49b4a26d21a80e7712a72528b215` | COMPLETED | local-store | `sha256:854f3c50b1cb...` | `linux/amd64` | 5 | n/a | 829.2 MiB | 8 | 3 | 6 | 22.244s | 174ms | 10.11s | - |
| `index.docker.io/library/erlang@sha256:0ac9b63db11be156be4e2834546e44aa0d7446aaffb05fedd4aea8c5a33ad998` | COMPLETED | local-store | `sha256:0ac9b63db11b...` | `linux/amd64` | 2 | n/a | 85.3 MiB | 10 | 2 | 5 | 3.397s | 30ms | 776ms | - |
| `index.docker.io/library/elixir@sha256:a2f0fe1bfd8a2f9cc91d913f4a12e6430e27e618720f753a514e2fff3d35f5a7` | COMPLETED | local-store | `sha256:a2f0fe1bfd8a...` | `linux/amd64` | 3 | n/a | 100.2 MiB | 10 | 2 | 5 | 2.425s | 36ms | 507ms | - |
| `index.docker.io/library/clojure@sha256:aa1b3f8a19462798a9662535d17173f501b3b45910aa7c3642aaddae41b096fa` | COMPLETED | local-store | `sha256:aa1b3f8a1946...` | `linux/amd64` | 9 | n/a | 323.6 MiB | 10 | 2 | 5 | 10.689s | 69ms | 5.067s | - |
| `index.docker.io/library/haskell@sha256:10500ef6abd41d210a74add013125065f92352b298999a9dfe296fb73deaccf7` | COMPLETED | local-store | `sha256:10500ef6abd4...` | `linux/amd64` | 5 | n/a | 4.1 GiB | 9 | 3 | 5 | 1m44.552s | 882ms | 12.921s | - |
| `index.docker.io/library/julia@sha256:0002771531bbae894f2532a5ae02ea71c30685440ca3bdaea0a43d17e65571e0` | COMPLETED | local-store | `sha256:0002771531bb...` | `linux/amd64` | 4 | n/a | 1.1 GiB | 9 | 3 | 5 | 29.247s | 237ms | 10.543s | - |
| `index.docker.io/library/gcc@sha256:b8a42d6804296fbe7a54e17e9d60c3100d9e8dbe7ef88c748cae2ddb00d63ba2` | COMPLETED | local-store | `sha256:b8a42d680429...` | `linux/amd64` | 8 | n/a | 1.5 GiB | 9 | 3 | 5 | 33.464s | 418ms | 12.322s | - |
| `index.docker.io/library/perl@sha256:2b59ca705cf3234d62c33e27ed573809498e476d45c4d0904550d0daced6a215` | COMPLETED | local-store | `sha256:2b59ca705cf3...` | `linux/amd64` | 4 | n/a | 185.3 MiB | 9 | 3 | 5 | 5.42s | 77ms | 1.84s | - |
| `index.docker.io/library/phpmyadmin@sha256:e4b3eb5305cd42d21512bb55def2bab52625d56df927ad4ee1864a9354c84d40` | COMPLETED | local-store | `sha256:e4b3eb5305cd...` | `linux/amd64` | 21 | n/a | 548.7 MiB | 11 | 5 | 1 | 29.989s | 195ms | 20.801s | - |
| `index.docker.io/library/ghost@sha256:4195f6c405e40230cd10c0770425cf500c1f542a96e9f6584c11649c150e5a89` | COMPLETED | local-store | `sha256:4195f6c405e4...` | `linux/amd64` | 10 | n/a | 580.9 MiB | 10 | 2 | 5 | 24.978s | 1.469s | 7.467s | - |
| `index.docker.io/library/drupal@sha256:2869a0abe45b7ce2bc6d7a35fabe447d06393c3ce613964b3a4f1d9660eb0e08` | COMPLETED | local-store | `sha256:2869a0abe45b...` | `linux/amd64` | 21 | n/a | 607.4 MiB | 10 | 6 | 1 | 32.496s | 327ms | 21.507s | - |
| `index.docker.io/library/joomla@sha256:f534566df4df83d2f6751d3406dc624e5af5b3c8d7f2b2101bf3c2f4e47b31f0` | COMPLETED | local-store | `sha256:f534566df4df...` | `linux/amd64` | 21 | n/a | 699.8 MiB | 8 | 4 | 5 | 14.008s | 269ms | 7.107s | - |
| `index.docker.io/library/mediawiki@sha256:406a08c7f2cf5a9c9cb590bbe27a21b4d3cb3268b0acf327fa7dd2727ff6b0be` | COMPLETED | local-store | `sha256:406a08c7f2cf...` | `linux/amd64` | 22 | n/a | 1.0 GiB | 10 | 6 | 1 | 32.592s | 491ms | 20.88s | - |
| `index.docker.io/library/nextcloud@sha256:81cb09055a20142521a267cea2bc27e6a81a065871c70850d209f08803567dbc` | COMPLETED | local-store | `sha256:81cb09055a20...` | `linux/amd64` | 23 | n/a | 1.3 GiB | 10 | 6 | 1 | 1m5s | 471ms | 48.605s | - |
| `index.docker.io/library/redmine@sha256:bfceeae10eb8dd20debc581e5c2213f53949c0195449d8cb4567e0bd522be07e` | COMPLETED | local-store | `sha256:bfceeae10eb8...` | `linux/amd64` | 12 | n/a | 471.8 MiB | 11 | 5 | 1 | 23.677s | 196ms | 16.346s | - |
| `index.docker.io/library/yourls@sha256:3631239a8cc0f3911f0cdae00f5475f48a65b9f2c9f120ba137766bba28c945c` | COMPLETED | local-store | `sha256:3631239a8cc0...` | `linux/amd64` | 23 | n/a | 511.3 MiB | 10 | 6 | 1 | 24.064s | 161ms | 13.748s | - |
| `index.docker.io/library/xwiki@sha256:ebef890add0eda3b07bca92db5fbc6fb3e3a10b3dc1cea260a2b26abc77d1f26` | COMPLETED | local-store | `sha256:ebef890add0e...` | `linux/amd64` | 21 | n/a | 1.5 GiB | 12 | 4 | 1 | 49.23s | 476ms | 22.722s | - |
| `index.docker.io/library/odoo@sha256:d5e3a26baa044867c826dddc09058f10e2582706bf83c146ea04fea889720c76` | COMPLETED | local-store | `sha256:d5e3a26baa04...` | `linux/amd64` | 9 | n/a | 2.2 GiB | 13 | 3 | 1 | 1m10.194s | 1.049s | 21.946s | - |
| `index.docker.io/library/rethinkdb@sha256:81ab2da93f66126dbd20580c1720e723111cc9a698ddb1a930ec3bd6cc47f8a8` | COMPLETED | local-store | `sha256:81ab2da93f66...` | `linux/amd64` | 5 | n/a | 117.3 MiB | 13 | 3 | 1 | 21.457s | 41ms | 16.541s | - |
| `index.docker.io/library/flink@sha256:ffb97a54a2b59960360d3b362e64f86ed5cab82621025eeed1399074b42a7b17` | COMPLETED | local-store | `sha256:ffb97a54a2b5...` | `linux/amd64` | 10 | n/a | 902.7 MiB | 10 | 2 | 5 | 23.329s | 183ms | 9.781s | - |
| `index.docker.io/library/fluentd@sha256:d912cf85f0229673e22462e69ad223d10804dd8ed32b4eecff6cb7adb3707f8d` | COMPLETED | local-store | `sha256:d912cf85f022...` | `linux/amd64` | 9 | n/a | 168.2 MiB | 13 | 3 | 1 | 18.26s | 77ms | 14.877s | - |
| `index.docker.io/library/logstash@sha256:553b09a32c788ace7c204a68feb7d0a406b7d700a059a318c00c2ca72e626c30` | COMPLETED | local-store | `sha256:553b09a32c78...` | `linux/amd64` | 12 | n/a | 864.7 MiB | 13 | 3 | 1 | 40.911s | 302ms | 24.739s | - |
| `index.docker.io/library/elasticsearch@sha256:b7b0f24e9b5e90656ffe69804b3a48907499ab2b9cd67f02b7af3aff1b026a89` | COMPLETED | local-store | `sha256:b7b0f24e9b5e...` | `linux/amd64` | 10 | n/a | 1.5 GiB | 14 | 2 | 1 | 53.555s | 298ms | 20.651s | - |
| `index.docker.io/library/kong@sha256:ad6cc0c8cca5b66b3cdab3bde7bc7ca973d4d820dd2c6651a7e3042f5428a76a` | COMPLETED | local-store | `sha256:ad6cc0c8cca5...` | `linux/amd64` | 4 | n/a | 371.6 MiB | 10 | 2 | 5 | 11.691s | 119ms | 5.643s | - |
| `index.docker.io/library/open-liberty@sha256:29dc1f49ed2ca1991c849bc974921ec655110995a2737256cfdfd29a334d1554` | COMPLETED | local-store | `sha256:29dc1f49ed2c...` | `linux/amd64` | 12 | n/a | 722.2 MiB | 12 | 4 | 1 | 31.942s | 205ms | 20.145s | - |
| `index.docker.io/library/ibm-semeru-runtimes@sha256:0601f9cd0e44ef93ddffef599b535d773475156f27bdcb0a2a7b6d4353baeed7` | COMPLETED | local-store | `sha256:0601f9cd0e44...` | `linux/amd64` | 4 | n/a | 352.7 MiB | 8 | 4 | 5 | 11.41s | 92ms | 3.842s | - |
| `index.docker.io/library/sapmachine@sha256:8c3afc896691208abee94e8db71cb972ed34a5c5b417610102261055b95d38a5` | COMPLETED | local-store | `sha256:8c3afc896691...` | `linux/amd64` | 2 | n/a | 242.1 MiB | 9 | 3 | 5 | 6.568s | 63ms | 2.545s | - |
| `index.docker.io/library/oraclelinux@sha256:9225108d00fb6611ebc4a5eced166f27d9dcfeaa539fb127be79425f0da5e745` | COMPLETED | local-store | `sha256:9225108d00fb...` | `linux/amd64` | 1 | n/a | 239.8 MiB | 8 | 3 | 6 | 8.653s | 99ms | 3.338s | - |
| `index.docker.io/library/fedora@sha256:15da97ed9aa94dd3d92c3925eb89520f6c80e07ea7ee24cba848d1f8b6912b3e` | COMPLETED | local-store | `sha256:15da97ed9aa9...` | `linux/amd64` | 1 | n/a | 176.9 MiB | 9 | 3 | 5 | 6.568s | 78ms | 2.27s | - |
| `index.docker.io/library/amazonlinux@sha256:c04a1012acc483977f61f7f91c28624a39a621e56a59781319a75dec528be9b6` | COMPLETED | local-store | `sha256:c04a1012acc4...` | `linux/amd64` | 1 | n/a | 143.2 MiB | 10 | 2 | 5 | 5.396s | 70ms | 1.735s | - |
| `index.docker.io/library/bash@sha256:589adbc588d8ef3c1ec3c68333faf4baf5dccb65d3cb50f6cf3d78cad2d6e1b0` | COMPLETED | local-store | `sha256:589adbc588d8...` | `linux/amd64` | 3 | n/a | 14.9 MiB | 10 | 2 | 5 | 1.884s | 7ms | 284ms | - |
| `index.docker.io/library/pypy@sha256:410aad485440d238a596fd5f847a99d3f7c11be895ce25c02b336f5c5d1733bb` | COMPLETED | local-store | `sha256:410aad485440...` | `linux/amd64` | 3 | n/a | 196.9 MiB | 9 | 3 | 5 | 5.211s | 61ms | 1.97s | - |
| `index.docker.io/library/composer@sha256:8de2184c6de224f4689e8f80ed5f5edaf0030b6b8b7839a22a2bcb6722ac87d0` | COMPLETED | local-store | `sha256:8de2184c6de2...` | `linux/amd64` | 14 | n/a | 214.7 MiB | 10 | 2 | 5 | 6.806s | 64ms | 2.825s | - |
| `index.docker.io/library/ros@sha256:00b8d47a6e6384a2834e3d01fa87ae767876543baa574f2d64a75c04ea33c698` | COMPLETED | local-store | `sha256:00b8d47a6e63...` | `linux/amd64` | 10 | n/a | 848.0 MiB | 9 | 3 | 5 | 22.798s | 361ms | 8.192s | - |
| `index.docker.io/library/storm@sha256:3f8c17e6ce43ac9ca6106458eb060ecf3096ba22422c4a04687b98e89cb68244` | COMPLETED | local-store | `sha256:3f8c17e6ce43...` | `linux/amd64` | 11 | n/a | 702.4 MiB | 9 | 3 | 5 | 20.621s | 212ms | 8.909s | - |
| `index.docker.io/library/spiped@sha256:7acba2c58083cf5246e055818bd95932bb6a26851e0123543a3c4b9681a07061` | COMPLETED | local-store | `sha256:7acba2c58083...` | `linux/amd64` | 6 | n/a | 8.3 MiB | 10 | 2 | 5 | 1.956s | 4ms | 281ms | - |
| `index.docker.io/library/irssi@sha256:62fbc3514f8ef0bf587137800856ee4dffbfaddf6ca8402501698a6491e3205d` | COMPLETED | local-store | `sha256:62fbc3514f8e...` | `linux/amd64` | 5 | n/a | 62.5 MiB | 11 | 1 | 5 | 2.573s | 29ms | 318ms | - |
| `index.docker.io/library/rakudo-star@sha256:0bc7542202ea3d9362ce15d90a601928f02b7657630fd131ad9d9847687b65b5` | COMPLETED | local-store | `sha256:0bc7542202ea...` | `linux/amd64` | 3 | n/a | 174.9 MiB | 9 | 3 | 5 | 5.822s | 52ms | 2.252s | - |
| `index.docker.io/library/mageia@sha256:d7e96eb4e2f3ac6b7bdf0caecf673836323ae409b304f195a98d22ab126217d9` | COMPLETED | local-store | `sha256:d7e96eb4e2f3...` | `linux/amd64` | 1 | n/a | 326.4 MiB | 8 | 4 | 5 | 10.971s | 120ms | 4.5s | - |
| `index.docker.io/library/caddy@sha256:e70b164da81ef698b3ad19af799ea6086ce6d9e48ed4079eb9fe26f6fbf14ee5` | COMPLETED | local-store | `sha256:e70b164da81e...` | `linux/amd64` | 5 | n/a | 63.3 MiB | 11 | 5 | 1 | 15.644s | 16ms | 13.298s | - |
| `index.docker.io/library/adminer@sha256:400af848ac3f57938abde4867677df1b195674d232c8896a27d111d04b9c088c` | COMPLETED | local-store | `sha256:400af848ac3f...` | `linux/amd64` | 17 | n/a | 110.8 MiB | 15 | 1 | 1 | 20.212s | 33ms | 16.945s | - |
| `index.docker.io/library/orientdb@sha256:26ddb8e116bf52c78b88db841295b576a1f627f995d024c5f9e5187d2dc40faa` | COMPLETED | local-store | `sha256:26ddb8e116bf...` | `linux/amd64` | 9 | n/a | 392.5 MiB | 11 | 5 | 1 | 22.826s | 148ms | 17.296s | - |
| `index.docker.io/library/swipl@sha256:2723fefd35116f92f68da22a487b1b01b584ac0b4b81fcd971c7ab2222f5d3e7` | COMPLETED | local-store | `sha256:2723fefd3511...` | `linux/amd64` | 3 | n/a | 265.6 MiB | 9 | 3 | 5 | 10.058s | 129ms | 3.168s | - |
| `index.docker.io/library/websphere-liberty@sha256:33db03751a2be1333b6b32d754bbefd3391a9b8013248c18847d49a03e807af8` | COMPLETED | local-store | `sha256:33db03751a2b...` | `linux/amd64` | 15 | n/a | 795.3 MiB | 12 | 4 | 1 | 35.048s | 270ms | 21.498s | - |
| `index.docker.io/library/lightstreamer@sha256:bb5f3f3f9585bb282acbe708235ede0d0a0990524d1383a5c3b2203a558b21f9` | COMPLETED | local-store | `sha256:bb5f3f3f9585...` | `linux/amd64` | 9 | n/a | 478.0 MiB | 14 | 2 | 1 | 28.24s | 165ms | 18.733s | - |
| `index.docker.io/library/convertigo@sha256:016dcebecb1e1b2b4233f32e12a9e46a748448848f5cee1daee16853114538a0` | COMPLETED | local-store | `sha256:016dcebecb1e...` | `linux/amd64` | 18 | n/a | 619.8 MiB | 11 | 5 | 1 | 30.013s | 168ms | 19.271s | - |
| `index.docker.io/library/buildpack-deps@sha256:890e8b5c0040e1deff5cc7dc7b4414e67069f79e3301afc4ec5bd49d64ef13e5` | COMPLETED | local-store | `sha256:890e8b5c0040...` | `linux/amd64` | 4 | n/a | 755.2 MiB | 9 | 3 | 5 | 19.925s | 236ms | 9.709s | - |
| `index.docker.io/library/clickhouse@sha256:07b744792d5b54da40ff7c5f18a9fcca929fd85f6cc317259dc5beb9dda1f90b` | COMPLETED | local-store | `sha256:07b744792d5b...` | `linux/amd64` | 8 | n/a | 861.9 MiB | 10 | 6 | 1 | 33.171s | 181ms | 18.765s | - |
| `index.docker.io/library/almalinux@sha256:838c2fafefb1a8a0d7f8cdbc3b0551c2a2b1eb0cd87aad6d62aecadb18311f1b` | COMPLETED | local-store | `sha256:838c2fafefb1...` | `linux/amd64` | 1 | n/a | 179.0 MiB | 9 | 3 | 5 | 6.55s | 80ms | 2.316s | - |
| `index.docker.io/library/neurodebian@sha256:4521313bfbf4b0dae3acd4e90b8fc5eb547d7df6b733dcfd89de1be8693e861b` | COMPLETED | local-store | `sha256:4521313bfbf4...` | `linux/amd64` | 5 | n/a | 137.1 MiB | 9 | 3 | 5 | 6.206s | 48ms | 600ms | - |
| `index.docker.io/library/hitch@sha256:91a93a77157131d0f9d09dc7aea80f565eb1a40fdf537014f5bc4b9fc741ce97` | COMPLETED | local-store | `sha256:91a93a771571...` | `linux/amd64` | 4 | n/a | 81.5 MiB | 10 | 6 | 1 | 15.363s | 33ms | 13.316s | - |
| `index.docker.io/library/eggdrop@sha256:2028d25c44a8fa7dbbfee1e1c9db809c5ba23eaa6516fbe84eb86c44886e1e04` | COMPLETED | local-store | `sha256:2028d25c44a8...` | `linux/amd64` | 7 | n/a | 30.4 MiB | 10 | 2 | 5 | 3.311s | 19ms | 1.056s | - |
| `index.docker.io/library/znc@sha256:472ffdd9e52f45e0fde51db668c513d594a17679ff4ef59973aee1f60d2450e7` | COMPLETED | local-store | `sha256:472ffdd9e52f...` | `linux/amd64` | 6 | n/a | 501.7 MiB | 9 | 3 | 5 | 15.967s | 152ms | 7.987s | - |
| `index.docker.io/library/rockylinux@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6` | COMPLETED | local-store | `sha256:d7be1c094cc5...` | `linux/amd64` | 1 | n/a | 167.4 MiB | 9 | 3 | 5 | 6.2s | 74ms | 2.138s | - |
| `index.docker.io/library/photon@sha256:3d7e9a35fd55277a056d9e1c54841e6b862a8df7e0caa56fa9c0453969f5329d` | COMPLETED | local-store | `sha256:3d7e9a35fd55...` | `linux/amd64` | 1 | n/a | 46.6 MiB | 8 | 3 | 6 | 2.292s | 16ms | 282ms | - |
| `index.docker.io/library/krakend@sha256:9f61092f8c627bb4d536e3977332ae4712113d603720b856d9951366bbf9b3ef` | COMPLETED | local-store | `sha256:9f61092f8c62...` | `linux/amd64` | 5 | n/a | 105.7 MiB | 13 | 3 | 1 | 16.929s | 27ms | 13.895s | - |
| `index.docker.io/library/groovy@sha256:fa81cdb39e5418c234ee7c85c251274be021bec9fb439e374af4f0663b106a53` | COMPLETED | local-store | `sha256:fa81cdb39e54...` | `linux/amd64` | 10 | n/a | 481.1 MiB | 10 | 2 | 5 | 13.902s | 121ms | 4.128s | - |
| `index.docker.io/library/haxe@sha256:64b8dbc020d84ad1e519f80c382619fb6dadeb2e2b01220c83c409a8648fa010` | COMPLETED | local-store | `sha256:64b8dbc020d8...` | `linux/amd64` | 6 | n/a | 410.9 MiB | 9 | 3 | 5 | 11.502s | 159ms | 5.366s | - |
| `index.docker.io/library/maven@sha256:308cba8b638ed7e4658cea3f8399066219466211c805f6d5728c3c9c7614661b` | COMPLETED | local-store | `sha256:308cba8b638e...` | `linux/amd64` | 9 | n/a | 364.7 MiB | 10 | 2 | 5 | 12.71s | 79ms | 6.266s | - |
