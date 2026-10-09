#!/usr/bin/env python3
# pem2tor.py — convert a PKCS8/PEM ed25519 private key to little-t-tor format.
#
# GoBalance signs with the VULNERABLE constant-nonce path ONLY when the
# master key file is in tor format ('== ed25519v1-secret: type0 ==' + the
# 64-byte expanded key a||h). A PEM/PKCS8 key (the file that
# 'gobalance generate-config' writes) takes the SAFE path, so the demo cannot
# recover anything from its descriptors. This tool rewrites the SAME key in
# tor format — the onion address is preserved, nothing else changes.
#
# Usage:
#   python3 pem2tor.py <in.pem> <out.torkey>
#   python3 pem2tor.py master.key hs_ed25519_secret_key
#
# It prints the onion address derived from the key so you can confirm it
# matches your current frontend address. Then point config.yaml 'key:' at the
# new file, restart gobalance, and capture a FRESH descriptor.

import base64
import hashlib
import sys

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493

def inv(x):
    return pow(x, P - 2, P)

D = -121665 * inv(121666) % P
I = pow(2, (P - 1) // 4, P)

def xrecover(y):
    xx = (y * y - 1) * inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x

BY = 4 * inv(5) % P
BX = xrecover(BY)
B = (BX % P, BY % P, 1, BX * BY % P)

def edwards_add(P1, P2):
    x1, y1, z1, t1 = P1
    x2, y2, z2, t2 = P2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    dd = z1 * 2 * z2 % P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)

def scalarmult(P1, e):
    Q = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            Q = edwards_add(Q, P1)
        P1 = edwards_add(P1, P1)
        e >>= 1
    return Q

def encodepoint(P1):
    x, y, z, t = P1
    zi = inv(z)
    x = x * zi % P
    y = y * zi % P
    out = bytearray(y.to_bytes(32, "little"))
    out[31] |= (x & 1) << 7
    return bytes(out)

def onion_address(pub):
    checksum = hashlib.sha3_256(b".onion checksum" + pub + b"\x03").digest()[:2]
    raw = pub + checksum + b"\x03"
    return base64.b32encode(raw).decode().lower().rstrip("=") + ".onion"

def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    pem_path, out_path = sys.argv[1], sys.argv[2]

    lines = [l.strip() for l in open(pem_path) if l.strip()]
    body = "".join(l for l in lines if not l.startswith("-----"))
    der = base64.b64decode(body)

    seed = der[-32:]
    if len(seed) != 32:
        sys.exit("ERROR: not a 32-byte-seed PKCS8 ed25519 key")

    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 63
    a[31] |= 64
    k = h[32:]

    blob = b"== ed25519v1-secret: type0 ==" + b"\x00" * 3 + bytes(a) + k
    with open(out_path, "wb") as f:
        f.write(blob)

    pub = encodepoint(scalarmult(B, int.from_bytes(a, "little")))
    print("tor-format key written : %s (%d bytes)" % (out_path, len(blob)))
    print("identity pubkey        : %s" % pub.hex())
    print("onion address          : %s" % onion_address(pub))
    print("\nNext: point config.yaml 'key:' at this file, restart gobalance,")
    print("capture a FRESH descriptor, then re-run: gbdemo attack -d desc.txt -a <onion>")

if __name__ == "__main__":
    main()
