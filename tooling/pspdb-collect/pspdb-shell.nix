{ pkgs ? import <nixpkgs> {} }:
# Pip-centric env: nix provides ONLY the python3.11 interpreter + C build deps
# (avoids the nixpkgs python3.11 package set, which fails eval on this channel
# — sphinx-9.x dropped 3.11 under the nix `selenium` closure). All Python deps
# come from PyPI via `pip install -e .` in a plain venv.
pkgs.mkShell {
  buildInputs = with pkgs; [
    python311
    gcc pkg-config
    curl.dev openssl.dev          # pycurl build
    libxml2.dev libxslt.dev       # lxml (psptool transitive) build
    zlib.dev
    cacert git
  ];
  shellHook = ''
    export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
    export GIT_SSL_CAINFO=$SSL_CERT_FILE
    export PYCURL_SSL_LIBRARY=openssl
  '';
}
