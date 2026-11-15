{
  description = "ConUnit - A Unit Testing Framework for OCI Containers";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { nixpkgs, ... }:
    let
      supportedSystems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          # Dockle comes from the upstream release and not from nixpkgs, because
          # the nixpkgs package does not build on aarch64-darwin (it needs
          # btrfs-progs). The release is pinned by version and by the sha256 of
          # each archive, read from the checksum file that the release itself
          # publishes (dockle_0.4.15_checksums.txt). The same version is pinned
          # for the evaluation instance in submission/eval-infra/tools.lock.
          dockleVersion = "0.4.15";
          dockleAssets = {
            aarch64-darwin = {
              file = "dockle_${dockleVersion}_macOS-ARM64.tar.gz";
              sha256 = "dc6120234cd74a40fedba84290f6b5c397c8f09c645063a3b59dce8283056847";
            };
            x86_64-darwin = {
              file = "dockle_${dockleVersion}_macOS-64bit.tar.gz";
              sha256 = "e6b68aca0e7776d857d7f5f226c6dae9b74d8905376636ac4ad93355ec84892d";
            };
            x86_64-linux = {
              file = "dockle_${dockleVersion}_Linux-64bit.tar.gz";
              sha256 = "8bfc9183d1d3d67800edb45bea4bb63ddf1d28bec5f89944075a07007d79caad";
            };
            aarch64-linux = {
              file = "dockle_${dockleVersion}_Linux-ARM64.tar.gz";
              sha256 = "14c2fbcd675afaa0f1717e97ab71eee178dabdef676066189f49bad0f53b8762";
            };
          };
          dockleAsset = dockleAssets.${system};
          dockle = pkgs.stdenvNoCC.mkDerivation {
            pname = "dockle-release";
            version = dockleVersion;
            src = pkgs.fetchurl {
              url = "https://github.com/goodwithtech/dockle/releases/download/v${dockleVersion}/${dockleAsset.file}";
              sha256 = dockleAsset.sha256;
            };
            sourceRoot = ".";
            dontConfigure = true;
            dontBuild = true;
            dontStrip = true;
            installPhase = ''
              runHook preInstall
              install -Dm755 dockle $out/bin/dockle
              runHook postInstall
            '';
          };
        in
        {
          default = pkgs.mkShell {
            packages = (with pkgs; [
              go
              just
              syft
              grype
              hadolint
              trivy
              container-structure-test
              jq
            ]) ++ [ dockle ];
            shellHook = ''
              echo "[INFO] ConUnit dev shell loaded (${system})"
              echo "[INFO] Go:      $(go version 2>&1)"
              echo "[INFO] Just:    $(just --version 2>&1)"
              echo "[INFO] Syft:    $(syft version 2>&1 | head -1)"
              echo "[INFO] Grype:   $(grype version 2>&1 | head -1)"
              echo "[INFO] Dockle:  $(dockle --version 2>&1 | head -1)"
            '';
          };
        }
      );
    };
}
