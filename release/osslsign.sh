#!/bin/sh

if test -z "$1"; then echo "usage: $0 <filename>"; exit 1; fi

set -x
V="${1##*xca-}"
V="${V%%-*}"

case "$OSTYPE" in
  darwin*)
    engine=/opt/homebrew/lib/engines-3/pkcs11.dylib
    module=/usr/local/lib/libSimplySignPKCS.dylib
    ;;
  linux*)
    engine=/usr/lib/x86_64-linux-gnu/engines-3/libpkcs11.so
    module=/opt/SimplySignDesktop/SimplySignPKCS_64-MS-1.0.20.so
    ;;
  *)
    echo "Unknown operating system $OSTYPE"
esac
pkcs11_id="9d8aad00d9fa2bc1f104e9744108d4551b53d2b7"

osslsigncode sign \
  -key "$pkcs11_id" -pkcs11cert "$pkcs11_id" \
  -pkcs11engine "$engine" -pkcs11module "$module" \
  -n "XCA ${V}" -i https://hohnstaedt.de/xca \
  -t http://timestamp.comodoca.com -h sha2 \
  -in "${1}" -out "${1}.signed" &&

exec mv "${1}.signed" "${1}"
