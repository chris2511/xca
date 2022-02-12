#!/bin/sh

if test -z "$1"; then echo "usage: $0 <filename>"; exit 1; fi

set -x
V="${1##xca-}"
V="${V%%-*}"

export PKCS11SPY=/opt/SimpleSign/libcrypto3PKCS.so

/usr/bin/osslsigncode sign -askpass -certs ~/osdch.crt -askpass \
  -key "pkcs11:object=Open%20Source%20Developer%2C%20Christian%20Hohnstaedt" \
  -pkcs11engine /usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so \
  -pkcs11module /usr/lib/x86_64-linux-gnu/pkcs11-spy.so \
  -n "XCA ${V}" -i https://hohnstaedt.de/xca \
  -t http://timestamp.comodoca.com -h sha2 \
  -in "${1}" -out "${1}.signed" 2>/dev/null &&

exec mv "${1}.signed" "${1}"
