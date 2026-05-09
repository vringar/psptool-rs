let
  pinnedNixpkgs = fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/0c88e1f2bdb93d5999019e99cb0e61e1fe2af4c5.tar.gz";
    sha256 = "004fbmvifmsbx4fx7ah5ichvj8ki6xlqajlsin5qq77dn0lf9ydb";
  };

  pinnedRustOverlay = fetchTarball {
    url = "https://github.com/oxalica/rust-overlay/archive/592e5dedf04f0eaff1ed0f01ce5db7407d9fc7be.tar.gz";
    sha256 = "014418sbd6ajfpzj7m8cckqy7ky0kcyha5w3fvilbppp8kq46pw5";
  };

  pkgs = import pinnedNixpkgs {
    overlays = [ (import pinnedRustOverlay) ];
  };

  # Pinned explicitly so the toolchain version is legible at a glance without
  # resolving the rust-overlay snapshot, and so a future overlay bump (which
  # would change the SHA above) doesn't quietly move rustc as a side effect.
  # Must stay in sync with Cargo.toml's `rust-version`.
  rustToolchain = pkgs.rust-bin.stable."1.95.0".default.override {
    extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
  };

  rustPlatform = pkgs.makeRustPlatform {
    cargo = rustToolchain;
    rustc = rustToolchain;
  };

  cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
in
{
  inherit pkgs rustToolchain;

  package = rustPlatform.buildRustPackage {
    pname = "psptool";
    inherit (cargoToml.workspace.package) version;

    # Limit src to files cargo needs so the giant vendor/test-corpus
    # submodule, .crosslink/, scripts/, and docs/ never enter the build sandbox.
    src = pkgs.lib.fileset.toSource {
      root = ./.;
      fileset = pkgs.lib.fileset.unions [
        ./Cargo.toml
        ./Cargo.lock
        ./crates
      ];
    };

    cargoLock.lockFile = ./Cargo.lock;

    # Build only the CLI; psptool-fixtures isn't a dep of psptool-cli and
    # we don't want it pulled into the release artifact.
    cargoBuildFlags = [ "--package" "psptool-cli" ];
    cargoTestFlags = [ "--workspace" ];

    meta = with pkgs.lib; {
      description = "AMD PSP firmware inspection and modification tool (Rust port of PSPTool)";
      homepage = "https://github.com/PSPReverse/psptool-rs";
      license = with licenses; [ mit asl20 ];
      mainProgram = "psptool";
    };
  };

  shell = pkgs.mkShell {
    name = "psptool-rs-dev";

    nativeBuildInputs = [
      rustToolchain
      pkgs.pkg-config
    ];

    buildInputs = [
      pkgs.cargo-nextest
      pkgs.cargo-insta
      pkgs.python3
    ];

    shellHook = ''
      export RUST_BACKTRACE=1
      export CARGO_TERM_COLOR=always

      if [ -d "$PWD/vendor/test-corpus/test_files" ] && [ -n "$(ls -A "$PWD/vendor/test-corpus/test_files" 2>/dev/null)" ]; then
        export PSPTOOL_TEST_CORPUS="$PWD/vendor/test-corpus"
      else
        echo "[psptool-rs] vendor/test-corpus is empty; corpus-gated integration tests will be skipped."
        echo "[psptool-rs] To enable: git submodule update --init vendor/test-corpus"
      fi

      echo "[psptool-rs] dev shell ready ($(rustc --version))"
    '';
  };
}
