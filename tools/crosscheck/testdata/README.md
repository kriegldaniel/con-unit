# Test data of tools/crosscheck

The two `dockle_0.4.15_*.json` files are real output of Dockle v0.4.15
(commit 54368575d2a0c34a82fb05c904b8207284a64891, built from the tag with
`-X github.com/goodwithtech/dockle/pkg.version=0.4.15`). The command was
`dockle --input <archive> --format json --exit-code 0`, run in an empty working
directory without any DOCKLE_ variable. The archives came from
`podman save --format docker-archive`.

- `dockle_0.4.15_alpine.json`: the official image alpine 3.24.3, unchanged.
- `dockle_0.4.15_seeded.json`: a local scratch image built on that alpine
  image. It adds a local file with ADD, the variables `DB_PASSWORD`, `GPG_KEY`
  and `PLAIN` with ENV (`GPG_KEY` is on the accepted-key list of Dockle, so it
  is not reported), the words `apt-get update`, `sudo` and `apt-get dist-upgrade`
  in RUN lines (no network was used), two accounts with the same UID, an empty
  `id_rsa` file, an empty `app/Dockerfile` file and `VOLUME /proc`.

Nothing in them depends on the host. The tests only read them.

The directory `golden` holds the generated outputs of the cross-check for a
synthetic study (`golden_test.go`). Regenerate them with
`go test ./tools/crosscheck -run Golden -update` after an intended change and
read the diff.
