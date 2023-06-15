#!/bin/sh

set -e

if [ ! -f ak.pub ]; then
  tpm2_createek -c ek.handle -G ecc -u ek.pub
  tpm2_createak -C ek.handle -c ak.ctx -u ak.pub -n ak.name

  # Remove with: tpm2_evictcontrol -c ak.handle
  tpm2_evictcontrol -o ak.handle -c ak.ctx

  rm ak.name ek.handle ak.ctx ek.pub

  # We are left with:
  # ak.pub
  # ak.handle
fi

for algo in "sha1" "sha256" "sha384"; do
  tpm2_quote -c ak.handle -l "$algo:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,23" -m "quote_${algo}.msg" -s "quote_${algo}.sig" -o "quote_${algo}.pcrs" -g sha256 -F serialized
done

# verify

for algo in "sha1" "sha256" "sha384"; do
  tpm2_checkquote -u ak.pub -m "quote_${algo}.msg" -s "quote_${algo}.sig" -f "quote_${algo}.pcrs" -g sha256
done

# register request

for algo in "sha1" "sha256" "sha384"; do
  for ty in "sig" "msg" "pcrs"; do
    base64 -w 0 <"quote_${algo}.${ty}" >"quote_${algo}.${ty}.b64"
  done

  (echo "\"$nonce\""; jq -Rs '.' "quote_${algo}.msg.b64"; jq -Rs '.' "quote_${algo}.sig.b64"; jq -Rs '.' "quote_${algo}.pcrs.b64") \
      | jq -s '{ { nonce: .[0], mode: { tpm: { msg: .[1], sig: .[2], pcrs: .[3] } } } }'
done

# TODO: also submit /sys/kernel/security/tpm0/binary_bios_measurements (to be processed by tpm2_eventlog)

for algo in "sha1" "sha256" "sha384"; do
  for ty in "sig" "msg" "pcrs"; do
    rm "quote_${algo}.${ty}" "quote_${algo}.${ty}.b64"
  done
done
