#!/usr/bin/env bash

INSTALL_DIR="Firefox Nightly.app/"
HG_DIR="/Users/erahm/dev/mozilla-unified/"
YEAR="2020"
MONTHS="01 02"
DAYS="01 05 10 15 20 25"

OUT="counts.txt"

for m in $MONTHS; do
  for d in $DAYS; do
    echo -n "$m/$d/$YEAR  " >> $OUT

    DATE=${YEAR}-${m}-${d}

    if test -n "$(find . -maxdepth 1 -name ${DATE}* -print -quit)"; then
      echo "Using existing"
    else
      # Download next build
      mozdownload -t daily --date ${DATE}
    fi

    # Install it
    mozinstall ${DATE}*

    # Remove installer
    #rm ${DATE}*

    # Run our analyzer on it
    python3 get-all-files-from-symbols.py "$INSTALL_DIR" "$HG_DIR" >> $OUT

    # Clear out installation
    rm -rf "$INSTALL_DIR"
  done
done
