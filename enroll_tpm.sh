#!/bin/sh

set -e

if [ -z "$1" ]; then
    echo "Usage: ./enroll_tpm.sh <path_to_luks_hdr>"
    exit 1
fi

echo -n "Enter LUKS password: "

read -s luks_password

if [ ! -f ak_tpm.pub ]; then
  echo "Creating new TPM attestation key"

  tpm2 createek -c ek.handle -G ecc -u ek.pub
  tpm2 createak -C ek.handle -c ak_tpm.ctx -u ak_tpm.pub -n ak_tpm.name

  # Remove with: tpm2_evictcontrol -c ak_tpm.handle
  tpm2 evictcontrol -o ak_tpm.handle -c ak_tpm.ctx

  rm ak_tpm.name ek.handle ak_tpm.ctx ek.pub

  # We are left with:
  # ak_tpm.pub
  # ak_tpm.handle
fi

for algo in "sha1" "sha256" "sha384"; do
  tpm2 quote -c ak_tpm.handle -l "$algo:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,23" -m "quote_${algo}.msg" -s "quote_${algo}.sig" -o "quote_${algo}.pcrs" -g sha256 -F serialized
done

# verify

for algo in "sha1" "sha256" "sha384"; do
  tpm2 checkquote -u ak_tpm.pub -m "quote_${algo}.msg" -s "quote_${algo}.sig" -f "quote_${algo}.pcrs" -g sha256
done

# register request

(
  cat ak_tpm.pub | base64 -w 0 | jq -Rs '{ mode: { Tpm: { pubkey: . } } }'
  cat "$1" | base64 -w 0 | jq -Rs '{ header: . }'
  echo "$luks_password" | base64 -w 0 | jq -Rs '{ key: . }'
  cat /sys/kernel/security/tpm0/binary_bios_measurements | base64 -w 0 | jq -Rs '{ mode: { Tpm: { eventlog: . } } }'
  for hty in "1" "256" "384"; do
    algo="sha$hty"
    for ty in "sig" "msg" "pcrs"; do
      base64 -w 0 <"quote_${algo}.${ty}" >"quote_${algo}.${ty}.b64"
    done

    (jq -Rs '.' "quote_${algo}.msg.b64"; jq -Rs '.' "quote_${algo}.sig.b64"; jq -Rs '.' "quote_${algo}.pcrs.b64") \
        | jq -s "{ mode: { Tpm: { quote$hty: { msg: .[0], sig: .[1], pcr: .[2] } } } }"
  done
) \
  | jq -s '.[0] * .[1] * .[2] * .[3] * .[4] * .[5] * .[6]' \
  | curl -X POST http://localhost:3000/machine/register -d @- -H 'Content-Type: application/json' -v

# TODO: also submit /sys/kernel/security/tpm0/binary_bios_measurements (to be processed by tpm2_eventlog)

for algo in "sha1" "sha256" "sha384"; do
  for ty in "sig" "msg" "pcrs"; do
    rm "quote_${algo}.${ty}" "quote_${algo}.${ty}.b64"
  done
done
