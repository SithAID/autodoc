#!/bin/bash

echo ""
echo "  AutoDoc — Local Dev on Termux"
echo "================================"
echo ""

if ! command -v node &>/dev/null; then
  echo "Node.js not found. Run: pkg install nodejs"
  exit 1
fi

NODE_VER=$(node -v | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VER" -lt 18 ]; then
  echo "Node.js 18+ required. Current: $(node -v)"
  echo "Run: pkg install nodejs"
  exit 1
fi

if [ ! -f ".dev.vars" ]; then
  cp .dev.vars.example .dev.vars
  echo "Created .dev.vars — add your API keys inside it"
fi

if [ ! -d "node_modules" ]; then
  echo "Installing wrangler..."
  npm install
fi

echo ""
echo "Starting local dev server..."
echo "Open: http://127.0.0.1:8788"
echo "Press Ctrl+C to stop"
echo ""

npx wrangler pages dev . \
  --compatibility-date=2024-09-23 \
  --port=8788 \
  --persist-to=./.wrangler/state
