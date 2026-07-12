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

  # Reference Python PSPTool — the upstream tool this project re-implements.
  # Pinned to the canonical GitHub master (PSPReverse/PSPTool), NOT a PyPI
  # release: the maintainers treat master as canonical and do not prioritise
  # releases, so the 3.4 sdist lags master (e.g. the type-0x5c 'SPI_ROM_CONFIG'
  # entry, file.py:149). The differential oracle must match our translation
  # source, which is that same master (`/tmp/psptool-ref`). Resolves the
  # version-skew (#61) that gated the multi-ROM AM5 corpus.
  #
  # Consumed only by the corpus-gated differential integration test (issue
  # #18): `psptool-cli/tests/differential.rs` shells out to `python3 -m psptool`
  # via the `PSPTOOL_REFERENCE` env var the dev shell exports.
  referencePsptool = pkgs.python3Packages.buildPythonPackage {
    pname = "psptool";
    version = "3.4.0"; # master @ edae097 (2026-04-20, merge of PR #84)
    format = "pyproject";
    src = pkgs.fetchFromGitHub {
      owner = "PSPReverse";
      repo = "PSPTool";
      rev = "edae097857e94b35d5203e644c177a3e1a3d444b";
      hash = "sha256-mEhjPehbG1MTtAjV0yAb2WQw5FtcT+bxs+tCzJTquA4=";
    };
    nativeBuildInputs = with pkgs.python3Packages; [ hatchling hatch-vcs ];
    propagatedBuildInputs = with pkgs.python3Packages; [ cryptography prettytable ];
    # hatch-vcs derives the version from VCS metadata, absent in the fetched
    # source tree — pin it explicitly (PEP 440) so the build does not fail.
    env.HATCH_VCS_PRETEND_VERSION = "3.4.0";
    doCheck = false;
    pythonImportsCheck = [ "psptool" ];
  };

  # A python3 interpreter that can `import psptool`. The differential test
  # invokes `${referencePython}/bin/python3 -m psptool ...`; running the
  # reference as a module (rather than its `psptool` console script) keeps it
  # off `PATH` and avoids any name collision with our own `psptool` binary.
  referencePython = pkgs.python3.withPackages (_: [ referencePsptool ]);
in
{
  inherit pkgs rustToolchain referencePython;

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

      # Reference Python PSPTool for the differential integration test (#18).
      # Unset elsewhere, the test self-skips; here it always resolves.
      export PSPTOOL_REFERENCE="${referencePython}/bin/python3"

      echo "[psptool-rs] dev shell ready ($(rustc --version))"
    '';
  };
}
