#!/bin/sh

(
  cd `dirname $0`
  echo '#define COMMITHASH "'
  git rev-parse HEAD
  git diff-index --quiet HEAD -- || test ! -d .git || echo "+local-changes"
  echo '"'
) 2>/dev/null | tr -d '\n' > "$1.new"

if cmp -s "$1" "$1.new"; then
  rm -f "$1.new"
else
  mv "$1.new" "$1"
fi
