set -e
cd /tmp/PSP-DB
echo "[1/2] nix env (interpreter + C headers) + fresh venv"
nix-shell /tmp/PSP-DB/pspdb-shell.nix --run '
  set -e
  rm -rf /tmp/PSP-DB/.venv
  python3.11 -m venv /tmp/PSP-DB/.venv
  . /tmp/PSP-DB/.venv/bin/activate
  pip -q install --upgrade pip setuptools wheel setuptools_scm 2>&1 | tail -1
  echo "[2/2] pip install -e . (all pspdb deps from PyPI: pony, psptool, selenium, pycurl, ...)"
  pip install -e . 2>&1 | tail -10
  echo "=== import smoke test ==="
  python -c "import pspdb, selenium, pony, psptool, pycurl, requests; from pspdb.strategies import asus; from pspdb.actions.get_devices import asus as d; print(\"IMPORTS OK — pspdb ready\")"
'
