#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

mkdir -p dist_all

pids=()

for i in *.py; do
  base="${i%.py}"
  outdir="out_${base}"
  mkdir -p "$outdir"

  # Build each script into its own dist/build to avoid collisions
  (
    cd "$outdir"
    wine pyinstaller --onefile "../$i" --distpath dist --workpath build --specpath spec
    # copy resulting exe to a common folder
    cp -v dist/*.exe "../dist_all/"
  ) &

  pids+=("$!")
done

# Wait for all parallel builds; fail if any fails
fail=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    fail=1
  fi
done
(( fail == 0 )) || { echo "At least one build failed"; exit 1; }

# Now it's safe: everything is built
scp dist_all/*.exe administrator@deploymaster-staging:/media/diskimages/drivers/

# Clean spec files you generated (in each outdir)
rm -rf out_*/spec
