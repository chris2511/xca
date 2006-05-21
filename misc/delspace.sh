#!/bin/sh

for i in $@; do
  cp "$i" /tmp/x
  cat /tmp/x |sed 's/[ \t]*$//' |sed 's/ *\t/\t/' > "$i"
done

