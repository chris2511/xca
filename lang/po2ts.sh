#!/bin/sh

ALL="$@"
test -n "$ALL" || ALL="tr fr sk"
for lang in $ALL; do
  lconvert -if po -of ts -i "${lang}.po" -o "xca_${lang}.ts"
done
