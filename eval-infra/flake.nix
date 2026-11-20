{
  description = "ConUnit - AWS Evaluation Infrastructure Shell";

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
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.opentofu
              pkgs.awscli2
              pkgs.jq
              pkgs.just
              pkgs.git
              pkgs.rsync
              pkgs.curl
              pkgs.openssh
              pkgs.shellcheck
            ];
            shellHook = ''
              echo "[INFO] ConUnit AWS evaluation shell loaded (${system})"
              echo "[INFO] Tools: tofu, aws, jq, just, git, rsync, curl, ssh, shellcheck"
              echo "[INFO] Start with: just --list   (validate, preflight, canary, full, destroy)"
            '';
          };
        }
      );
    };
}
