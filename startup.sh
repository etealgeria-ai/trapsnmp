#!/bin/sh
set -eu
cd /workspace
node scripts/preview.mjs stop || true
if curl -sf -o /dev/null --max-time 2 http://127.0.0.1:8080/; then
  exit 0
fi
python3 -c "import asyncua, pysnmp" 2>/dev/null || pip3 install -q -r /workspace/requirements.txt
pip3 install -q -U aiohttp
python3 -m trapsnmp >>/tmp/trapsnmp.log 2>&1 &
i=0
while [ "$i" -lt 40 ]; do
  if curl -sf -o /dev/null --max-time 1 http://127.0.0.1:8080/; then
    exit 0
  fi
  i=$((i + 1))
  sleep 0.5
done
exit 0
