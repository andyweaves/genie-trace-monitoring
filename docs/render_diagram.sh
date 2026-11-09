#!/usr/bin/env bash
# Re-render the architecture diagram PNG from its SVG source.
# Run after editing docs/table_guide_architecture.svg, then redeploy the bundle.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SVG="$HERE/table_guide_architecture.svg"
OUT="$HERE/../src/notebooks/images/table_guide_architecture.png"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
if [ -x "$CHROME" ]; then
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars \
    --window-size=1320,420 --force-device-scale-factor=2 \
    --screenshot="$OUT" "file://$SVG" >/dev/null 2>&1
elif command -v rsvg-convert >/dev/null; then
  rsvg-convert -w 2640 -o "$OUT" "$SVG"
else
  echo "Need Google Chrome or rsvg-convert to render the diagram" >&2; exit 1
fi
echo "wrote $OUT"
