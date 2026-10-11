#!/usr/bin/env bash
# xca-run.sh - Linux wrapper for XCA cli-certgen execution
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
XCA_BIN="${XCA_BIN:-${REPO_DIR}/build/xca}"

if [[ ! -x "${XCA_BIN}" ]]; then
  echo "Error: XCA binary not found at ${XCA_BIN}. Build it first." >&2
  exit 1
fi

# Load database password from .env
if [[ -z "${XCA:-}" ]]; then
  for env_candidate in "${SCRIPT_DIR}/.env" "${PWD}/.env" "/home/john/GitHub/nucleix-it/aws-agent/.env"; do
    if [[ -f "${env_candidate}" ]]; then
      # Extract only XCA variable safely
      XCA_VAL=$(grep -E '^XCA=' "${env_candidate}" | cut -d'=' -f2- | tr -d '"\r\n' || true)
      if [[ -n "${XCA_VAL}" ]]; then
        export XCA="${XCA_VAL}"
        break
      fi
    fi
  done
fi

if [[ -z "${XCA:-}" ]]; then
  echo "Error: XCA database password not found in environment or .env file." >&2
  exit 1
fi

# Safety check: refuse --verbose as it can print SQL rows including encrypted key blobs
for arg in "$@"; do
  if [[ "${arg}" == "--verbose" ]]; then
    echo "Error: --verbose is refused by xca-run.sh to prevent key blob exposure in logs." >&2
    exit 1
  fi
done

# Run headless if DISPLAY is not set
if [[ -z "${DISPLAY:-}" ]]; then
  export QT_QPA_PLATFORM="offscreen"
fi

# Execute XCA with password passed via env:XCA
"${XCA_BIN}" "--password=env:XCA" "$@"
