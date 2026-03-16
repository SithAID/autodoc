#!/bin/bash
cd "$(dirname "$0")"

if ! command -v node &>/dev/null; then
  echo "  Node.js not found."
  if [ -d "/data/data/com.termux" ]; then
    echo "  Run: pkg install nodejs"
  else
    echo "  Install from: https://nodejs.org"
  fi
  exit 1
fi

node start.js
