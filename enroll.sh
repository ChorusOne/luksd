#!/bin/sh

set -e

if [ ! -f ak.pub ]; then
  tpm2 createek -c ek.handle -G ecc -u ek.pub
  tpm2 createak -C ek.handle -c ak.ctx -u ak.pub -n ak.name

  # Remove with: tpm2_evictcontrol -c ak.handle
  tpm2 evictcontrol -o ak.handle -c ak.ctx

  rm ak.name ek.handle ak.ctx ek.pub

  # We are left with:
  # ak.pub
  # ak.handle
fi

for algo in "sha1" "sha256" "sha384"; do
  tpm2 quote -c ak.handle -l "$algo:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,23" -m "quote_${algo}.msg" -s "quote_${algo}.sig" -o "quote_${algo}.pcrs" -g sha256 -F serialized
done

# verify

for algo in "sha1" "sha256" "sha384"; do
  tpm2 checkquote -u ak.pub -m "quote_${algo}.msg" -s "quote_${algo}.sig" -f "quote_${algo}.pcrs" -g sha256
done

# register request

(
  cat ak.pub | base64 -w 0 | jq -Rs '{ mode: { Tpm: { pubkey: . } } }'
  cat hdr.img | base64 -w 0 | jq -Rs '{ header: . }'
  cat password | base64 -w 0 | jq -Rs '{ key: . }'
  for hty in "1" "256" "384"; do
    algo="sha$hty"
    for ty in "sig" "msg" "pcrs"; do
      base64 -w 0 <"quote_${algo}.${ty}" >"quote_${algo}.${ty}.b64"
    done

    (jq -Rs '.' "quote_${algo}.msg.b64"; jq -Rs '.' "quote_${algo}.sig.b64"; jq -Rs '.' "quote_${algo}.pcrs.b64") \
        | jq -s "{ mode: { Tpm: { quote$hty: { msg: .[0], sig: .[1], pcr: .[2] } } } }"
  done
) \
  | jq -s '.[0] * .[1] * .[2] * .[3] * .[4] * .[5]' \
  | curl -X POST http://localhost:3000/machine/register -d @- -H 'Content-Type: application/json' -v

# TODO: also submit /sys/kernel/security/tpm0/binary_bios_measurements (to be processed by tpm2_eventlog)

for algo in "sha1" "sha256" "sha384"; do
  for ty in "sig" "msg" "pcrs"; do
    rm "quote_${algo}.${ty}" "quote_${algo}.${ty}.b64"
  done
done
