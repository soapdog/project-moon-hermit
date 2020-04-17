#!/bin/sh
cap_hex=${1?shs cap key}
pk_hex=${2?server public key}

cap_b64="$(echo -n "$cap_hex" | xxd -r -p | base64)"
pk_b64="$(echo -n "$pk_hex" | xxd -r -p | base64)"

exec sbotc -T -c "$cap_b64" -k "$pk_b64"
