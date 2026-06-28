{
  description = "LLM-based Code Vulnerability Scanner — NixOS development environment";

  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs   = import nixpkgs { inherit system; config.allowUnfree = true; };

        # ── Pin Python 3.12 explicitly ─────────────────────────────────────────
        # python3.14 (Arch default) breaks pydantic-core and tokenizers.
        # python312 from nixpkgs gives stable, fully-wheeled support for all
        # packages in requirements.txt — no source compilation needed.
        python = pkgs.python312;

        # ── System libraries needed by pip-compiled packages ──────────────────
        buildDeps = with pkgs; [
          # C toolchain (some pip packages vendor C code)
          gcc
          gnumake
          pkg-config
          cmake

          # Rust (pydantic-core, tokenizers build via maturin — but with the
          # right Python version pre-built wheels are used instead)
          cargo
          rustc

          # Libraries that pip packages link against
          openssl
          openssl.dev
          zlib
          zlib.dev
          libffi
          sqlite

          # Needed by sentence-transformers' native extensions
          blas
          lapack

          # Chromadb / hnswlib
          stdenv.cc.cc.lib
        ];

        # ── Runtime tools ─────────────────────────────────────────────────────
        runtimeTools = with pkgs; [
          python
          python.pkgs.pip
          python.pkgs.virtualenv

          ollama        # local LLM inference server
          git
          curl
          wget
        ];

      in {
        # ── nix develop ───────────────────────────────────────────────────────
        devShells.default = pkgs.mkShell {
          buildInputs = buildDeps ++ runtimeTools;

          # Environment variables pip and cargo need to find system libs
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
            pkgs.stdenv.cc.cc.lib
            pkgs.openssl
            pkgs.zlib
            pkgs.libffi
          ];

          PKG_CONFIG_PATH = pkgs.lib.makeSearchPathOutput "dev" "lib/pkgconfig" [
            pkgs.openssl
            pkgs.zlib
            pkgs.libffi
          ];

          # Tell pip to prefer pre-built wheels over source builds.
          # Combined with Python 3.12, this means pydantic-core and tokenizers
          # install from wheels with ZERO Rust / C compilation.
          PIP_PREFER_BINARY = "1";
          PIP_NO_BUILD_ISOLATION = "0";

          shellHook = ''
            echo ""
            echo "🔒 Code Vulnerability Scanner — Nix Dev Shell"
            echo "   Python: $(python --version)"
            echo "   Ollama: $(ollama --version 2>/dev/null || echo 'not started')"
            echo ""

            # ── Create venv with the Nix-provided Python 3.12 ─────────────────
            if [ ! -d ".venv" ]; then
              echo "Creating Python 3.12 virtual environment..."
              python -m venv .venv
              echo "Activating..."
            fi

            source .venv/bin/activate

            # ── Install pip dependencies (idempotent) ──────────────────────────
            # The sentinel file prevents re-running pip on every nix develop.
            if [ ! -f ".venv/.nix_installed" ]; then
              echo "Installing Python dependencies..."
              pip install --prefer-binary --upgrade pip -q
              pip install --prefer-binary -r requirements.txt -q
              pip install -e . -q
              touch .venv/.nix_installed
              echo "Dependencies installed."
            fi

            echo "─────────────────────────────────────────────"
            echo "  Next steps:"
            echo "    cp .env.example .env              # first time only"
            echo "    ollama serve                      # in a separate shell"
            echo "    ollama pull codellama:7b"
            echo "    python scripts/setup_db.py        # first time only"
            echo "    streamlit run src/vuln_scanner/ui/app.py"
            echo "─────────────────────────────────────────────"
          '';
        };

        # ── nix run (launches the Streamlit UI directly) ──────────────────────
        apps.default = flake-utils.lib.mkApp {
          drv = pkgs.writeShellScriptBin "vuln-scanner-ui" ''
            cd ${self}
            source .venv/bin/activate 2>/dev/null || true
            ${python}/bin/python -m streamlit run src/vuln_scanner/ui/app.py
          '';
        };
      });
}
