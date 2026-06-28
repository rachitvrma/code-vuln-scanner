# shell.nix
# ---------
# For NixOS users who aren't using flakes yet, or who prefer `nix-shell`.
# Usage:  nix-shell
#
# If you have flakes enabled, prefer:  nix develop

{ pkgs ? import <nixpkgs> { config.allowUnfree = true; } }:

let
  python = pkgs.python312;
in
pkgs.mkShell {
  buildInputs = [
    python
    python.pkgs.pip
    python.pkgs.virtualenv

    pkgs.ollama
    pkgs.git

    # Build tools (only needed if any package falls back to source compilation)
    pkgs.gcc
    pkgs.gnumake
    pkgs.pkg-config
    pkgs.openssl
    pkgs.openssl.dev
    pkgs.zlib
    pkgs.zlib.dev
    pkgs.libffi
    pkgs.cargo
    pkgs.rustc
    pkgs.stdenv.cc.cc.lib
  ];

  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
    pkgs.stdenv.cc.cc.lib
    pkgs.openssl
    pkgs.zlib
    pkgs.libffi
  ];

  PIP_PREFER_BINARY = "1";

  shellHook = ''
    echo "🔒 Code Vulnerability Scanner (nix-shell, Python 3.12)"
    if [ ! -d ".venv" ]; then
      python -m venv .venv
    fi
    source .venv/bin/activate
    if [ ! -f ".venv/.nix_installed" ]; then
      pip install --prefer-binary -r requirements.txt -q
      pip install -e . -q
      touch .venv/.nix_installed
    fi
  '';
}
