{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-parts.url = "github:hercules-ci/flake-parts";
    x52 = {
      url = "github:x52dev/nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-parts.follows = "flake-parts";
    };
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs@{ flake-parts, naersk, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      perSystem = { pkgs, config, inputs', system, lib, ... }:
        let
          x52just = inputs'.x52.packages.x52-just;
          naersk' = pkgs.callPackage naersk { };
          macSdk = [ ] ++ lib.optional pkgs.stdenv.isDarwin [
            pkgs.pkgsBuildHost.libiconv
          ];
        in
        rec
        {
          formatter = pkgs.nixpkgs-fmt;

          packages.default = naersk'.buildPackage {
            src = ./.;
            buildInputs = macSdk;
            doCheck = true;
          };

          devShells.default = pkgs.mkShell {
            buildInputs = [ x52just ];

            packages = [
              config.formatter
              pkgs.just
              pkgs.nodePackages.prettier
              pkgs.taplo
              pkgs.watchexec
            ] ++ macSdk;

            shellHook = ''
              mkdir -p .toolchain
              cp --update=older ${x52just}/*.just .toolchain/
            '';
          };
        };
    };
}
