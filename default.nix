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
  # Pinned to a GitHub revision, NOT a PyPI release: the maintainers treat
  # master as canonical and do not prioritise releases, so the 3.4 sdist lags
  # master (e.g. the type-0x5c 'SPI_ROM_CONFIG' entry, file.py:149). The
  # differential oracle must match our translation source (`/tmp/psptool-ref`),
  # which is master edae097 plus the decode-verified signal
  # (`header_file.py:191-276`, `psptool.py:267-271`) on vringar/PSPTool
  # claude-main @ 241629b — the revision the consumers pin and the one the
  # `decodeVerified` ladder (psptool-core `body.rs`) and the Python bindings
  # were translated from. Resolves the version-skew (#61) that gated the
  # multi-ROM AM5 corpus.
  #
  # Consumed by the corpus-gated integration tests through the
  # `PSPTOOL_REFERENCE` env var the dev shell exports: the differential test
  # (`psptool-cli/tests/differential.rs`, `python3 -m psptool`) and the
  # bindings' parity test (`psptool-py/tests/corpus_parity.rs`).
  referencePsptool = pkgs.python3Packages.buildPythonPackage {
    pname = "psptool";
    version = "3.4.0"; # vringar/PSPTool claude-main @ 64c21462 (decode-verified + try-both signature verify)
    format = "pyproject";
    src = pkgs.fetchFromGitHub {
      owner = "vringar";
      repo = "PSPTool";
      rev = "64c2146292d69825a52fb8a2d45f3f3110ee1e10";
      hash = "sha256-pMa58+D+Kj2M9vHDAMK3JtxOJ0gdC/QzcTNFuPTKJxc=";
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

  # Limit src to files cargo needs so the giant vendor/test-corpus
  # submodule, .crosslink/, scripts/, and docs/ never enter the build sandbox.
  # `./crates` carries every workspace member, including the Python package
  # sources and tests of `crates/psptool-py`.
  workspaceSrc = pkgs.lib.fileset.toSource {
    root = ./.;
    fileset = pkgs.lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./crates
    ];
  };

  # The `psptool` Python package (crates/psptool-py: pyo3 abi3 extension +
  # re-export modules, built by maturin) for a given Python package set — a
  # drop-in for the reference tool's `import psptool`. Consumers on another
  # interpreter version call e.g. `pythonFor pkgs.python312Packages`.
  pythonFor = pythonPackages: pythonPackages.buildPythonPackage {
    pname = "psptool";
    inherit (cargoToml.workspace.package) version;
    pyproject = true;
    src = workspaceSrc;
    buildAndTestSubdir = "crates/psptool-py";
    cargoDeps = rustPlatform.importCargoLock { lockFile = ./Cargo.lock; };
    # The pinned toolchain first: maturinBuildHook propagates nixpkgs' default
    # cargo/rustc, which is older than the workspace's `rust-version`.
    nativeBuildInputs = [
      rustToolchain
      rustPlatform.cargoSetupHook
      rustPlatform.maturinBuildHook
    ];
    # The corpus-free API suite (synthetic image; parse, decode, edit,
    # re-sign, PEM keys) against the installed package.
    checkPhase = ''
      runHook preCheck
      ${pythonPackages.python.interpreter} ${workspaceSrc}/crates/psptool-py/tests/test_api.py -v
      runHook postCheck
    '';
    pythonImportsCheck = [ "psptool" "psptool.header_file" ];
    meta = with pkgs.lib; {
      description = "PSPTool's Python API (import psptool) backed by psptool-rs";
      homepage = "https://github.com/PSPReverse/psptool-rs";
      license = with licenses; [ mit asl20 ];
    };
  };
in
{
  inherit pkgs rustToolchain referencePython pythonFor;

  python = pythonFor pkgs.python3Packages;

  package = rustPlatform.buildRustPackage {
    pname = "psptool";
    inherit (cargoToml.workspace.package) version;

    src = workspaceSrc;

    cargoLock.lockFile = ./Cargo.lock;

    # Build only the CLI; psptool-fixtures isn't a dep of psptool-cli and
    # we don't want it pulled into the release artifact.
    cargoBuildFlags = [ "--package" "psptool-cli" ];
    # psptool-py's tests link libpython and drive a Python interpreter; they
    # run in the `python` attribute's check phase and the dev shell instead.
    cargoTestFlags = [ "--workspace" "--exclude" "psptool-py" ];

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
