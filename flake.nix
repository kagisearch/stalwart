{
  description = "Development shell for building Stalwart (Kagi fork)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    { flake-parts, ... }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-darwin"
      ];
      perSystem =
        { pkgs, system, ... }:
        let
          # Pinned to match the CI images (Dockerfile / Dockerfile.build).
          rustToolchain = pkgs.rust-bin.stable."1.96.0".default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
              "clippy"
              "rustfmt"
            ];
          };

          # Feature set the kagi-email local dev build uses (kagi-email/flake.nix,
          # overlays.default -> stalwart.cargoBuildFeatures). The image Cloud
          # Build deploys to dev and prod is built from Dockerfile, which adds
          # nats and redis on top of this.
          kagiFeatures = "postgres s3";

          # Feature set upstream CI builds for the release binaries (ci.yml).
          ciFeatures = "sqlite postgres mysql rocks s3 redis azure nats enterprise";
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.rust-overlay.overlays.default ];
          };

          devShells.default = pkgs.mkShell {
            # The clang wrapper injects -D_FORTIFY_SOURCE, which glibc turns
            # into a #warning at -O0. tikv-jemalloc-sys runs its configure
            # checks with -Werror, so any debug-profile build (cargo check,
            # cargo test) fails with "cannot determine return type of
            # strerror_r" unless fortify is left out of the wrapper flags.
            hardeningDisable = [ "fortify" ];

            nativeBuildInputs = with pkgs; [
              rustToolchain

              # Only the `rocks` feature (librocksdb-sys) needs bindgen, so
              # the Kagi Mail build never touches these; they are here so the
              # CI feature set and the test suite (STORE=RocksDb) build too.
              rustPlatform.bindgenHook
              clang

              # aws-lc-sys, librocksdb-sys, tikv-jemalloc-sys
              cmake
              perl
              gnumake
              pkg-config

              # Same helpers the CI build image installs.
              git
              curl
              jq

              # Optional but useful; used by ci.yml for compile caching.
              sccache
            ];

            buildInputs = with pkgs; [
              openssl
              zstd
              lz4
              bzip2
              zlib
              # FoundationDB is deliberately not included: the crate is built
              # against the 7.4 client API (features = ["fdb-7_4"]) and nixpkgs
              # currently ships 7.3. Install the 7.4 client manually to build
              # with --features foundationdb.
            ];

            env = {
              # Mirrors env from .github/workflows/ci.yml and Dockerfile.build.
              CARGO_TERM_COLOR = "always";
              CARGO_NET_RETRY = "10";
              CARGO_NET_GIT_FETCH_WITH_CLI = "true";

              # Mirrors env from .github/workflows/test.yml.
              STORE = "RocksDb";
              RUST_MIN_STACK = "16777216";

              # Feature sets, so scripts and aliases can reuse them.
              STALWART_KAGI_FEATURES = kagiFeatures;
              STALWART_CI_FEATURES = ciFeatures;
            };

            shellHook = ''
              echo "Stalwart dev shell — $(rustc --version)"
              echo "Kagi Mail build:  cargo build --release -p stalwart --no-default-features --features \"${kagiFeatures}\""
              echo "CI build:         cargo build --release -p stalwart --no-default-features --features \"${ciFeatures}\""
              echo "Tests need a running Docker daemon (testcontainers)."
            '';
          };
        };
    };
}
