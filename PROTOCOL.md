# luksd protocol

## Background

`luksd` protocol is based on McCallum-Relyea exchange, as inspired by
[tang](https://github.com/latchset/tang?tab=readme-ov-file#provisioning).

The following security considerations are taken into account when designing the
protocol:

- Post-quantum crypto.
  - Attackers can easily break EC crypto.
  - We have PQ crypto algorithms, but they are not proven.
  - Best way to protect against key leak is to transfer as little material over
    the wire.
    - Ideally, only when enrolling.
- Machine compromise.
  - Assume machines X and Y are compromised, at hardware layer.
    - X is not using a TPM.
    - Y is using a TPM.
  - X's low security status must not be leveraged to decrypt Y.

Thus, `luksd` server uses different set of keys for different trust models.
Optionally, `luksd` can use unique key per given machine. Upon enrolling a
server/disk-image, a data trust mode must be specified. It specifies whether a
machine shall use a TPM or not.

## Protocol

### Step 1: Provisioning

Suppose we have a machine `M`, that we want to provision.

First, an authorized client `A` selects the data trust mode `T` (`tpm` or
`plaintext`), and generates a random machine ID `I`, to be sent to the `luksd`
server.

Then, HTTP POST request to `provision/<T>/<I>`.

On success: 200 OK, server's public EC key `S` (jwk format).

Then, create EC key-pair `C` for the machine, and derive LUKS key `K`.

The previous steps, expressed as a protocol:

```
A -> S : {T, I}
S : s = g * S
S -> A : {s}
A : c = g * C
A : K = s * C
```

Afterwards, `C` is thrown away.

### Step 2: Deploying

Exact steps of deployment are outside the scope of `luksd`, but there are shared
properties among the deployments, and there are 2 proposed methods for final
delivery.

In all methods, `T`, `I`, and `c` are baked into the disk of machine `M`, and
there exists a volume `L`, encrypted with `K`. After everything is set up, `K`
is thrown away.

#### Option 1: Image based delivery

In this method, we build an image `i`, destined for `M`, and bake all config
inside of it. `T`, `I`, and `c` are baked into the image in plain-text,
made accessible from initramfs. `L` is set up with `K`, and `K` is thrown away.

Then, we copy `i` onto the machine and reboot into it.

#### Option 2: Manual setup

`T`, `I`, and `c` are copied to `M`. A LUKS volume `L` is set up, using `K`.
This can be done either by transferring `K` onto the machine, or building a LUKS
header on `A`, and copying it over using `dd`. The possibilities are endless!

### Step 3: Unlocking

Now, upon each boot, `M` will run the unlock protocol against `S` to reconstruct
`K`.

#### Step 3.0: TPM enrolling

Machines, backed by TPM `T`, will first need to enroll a key to securely perform
cryptographic operations on.

First, if we haven't already, create a new TPM attestation key:

```
# Check if we need to submit the attestation key to the server.
export first_time=true

tpm2 createek -c ek.handle -G ecc -u ek.pub
tpm2 createak -C ek.handle -c ak_tpm.ctx -u ak_tpm.pub -n ak_tpm.name

# Remove with: tpm2_evictcontrol -c ak_tpm.handle
tpm2 evictcontrol -o ak_tpm.handle -c ak_tpm.ctx

rm ak_tpm.name ek.handle ak_tpm.ctx ek.pub

# We are left with:
# ak_tpm.pub
# ak_tpm.handle
```

Then, HTTP GET recent nonce value `N` for the machine from `nonce/<I>`.

Afterwards, using said attestation key, acquire hashed TPM PCR values:

```
for algo in "sha1" "sha256" "sha384"; do
  tpm2 quote -c ak_tpm.handle -l "$algo:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,23" -q "<N>" -m "quote_${algo}.msg" -s "quote_${algo}.sig" -o "quote_${algo}.pcrs" -g sha256 -F serialized
done
```

Then, produce verification information JSON `V`, from the above data:

```
{
  "tpm": {
    "nonce": N,
    "ak": <base64 ak_tpm.pub> if first_time,
    "eventlog": <base64 /sys/kernel/security/tpm0/binary_bios_measurements>,
    "quotes": {
      "quote_sha1": {
        "msg": <base64 quote_sha1.msg>,
        "sig": <base64 quote_sha1.sig>,
        "pcr": <base64 quote_sha1.pcrs>,
      },
      "quote_sha256": { ... },
      "quote_sha384": { ... }
    }
  }
}
```

#### Step 3.1: Unlock request

The client produces an ephemeral key pair `E`, and computes `x` by adding `e` to
`c`.

Then, HTTP POST request to `unlock/<T>/<I>`. Input JSON body, as follows:

```
{
  "x": <jwk x>,
  "verif": V | null
}
```

On success: 202 ACCEPTED, session ID `U` as response.

#### Step 3.2: Poll ready

HTTP GET request to `session/<U>/poll_ready`. Optional query parameter `short`,
to indicate short polling (by default `luksd` will block for 10 seconds before
returning).

On success: 200 OK, with the following JSON body:

```
{
  "s": <jwk s>,
  "y": <jwk y>,
}
```

##### Step 3.2.1: Reject/Approve request

Step 3.2 blocks, because the client may be not TPM backed, may be enrolling for
the first time, or some parts of the boot configuration, such as kernel, have
changed. In these cases, manual human approval is needed. `luksd` provides admin
API, but we are not detailing it in this protocol document.

#### Step 3.3: Recover encryption key

Finally, we compute `z` by multiplying `s` by `E` and compute `K` by subtracting `z` from `y`.

#### Steps 3.1-3.3 summary

As a protocol, we perform the following steps:

```
M : e = g * E
M : x = c + e
M -> S : {x, V}
S : y = x * S
S -> M : {s, y}
M : z = s * E
M : K = y - z
```

#### Step 3.4: Unlock the volume

Use `K` to unlock the LUKS volume `L`.
