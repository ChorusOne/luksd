#/bin/sh

set -e

nonce=$(curl localhost:3000/machine/nonce)

echo "$nonce"

for algo in "sha1" "sha256" "sha384"; do
  tpm2 quote -c ak.handle -l "$algo:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,23" -q "$nonce" -m "quote_${algo}.msg" -s "quote_${algo}.sig" -o "quote_${algo}.pcrs" -g sha256 -F serialized
done

# verify locally

for algo in "sha1" "sha256" "sha384"; do
  tpm2 checkquote -u ak.pub -m "quote_${algo}.msg" -s "quote_${algo}.sig" -f "quote_${algo}.pcrs" -q "$nonce" -g sha256
done

(
  echo "{ \"nonce\": \"$nonce\" }"
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
  | jq -s '.[0] * .[1] * .[2] * .[3] * .[4]' \
  | curl -X POST http://localhost:3000/machine/key -d @- -H 'Content-Type: application/json' -v

