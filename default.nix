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

  rustToolchain = pkgs.rust-bin.stable.latest.default.override {
    extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
  };
in
{
  inherit pkgs rustToolchain;

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
