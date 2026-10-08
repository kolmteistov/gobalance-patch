# GoBalance Security Patch & PoC

**Advisory package for `gitlab.com/n0tr1v/gobalance`** — master branch, commit `bb1b0f3` ("fix crash").
Status: **CRITICAL — two independent full-takeover paths.** The upstream `patch1` branch fixes **neither** of them.

This package contains a complete security patch, an end-to-end proof-of-concept for both attack paths, and regression tests proving the fixes hold. It accompanies the full vulnerability analysis report ("Laporan Analisis Keamanan GoBalance") prepared in connection with the recent onion-domain takeover incidents affecting two forums. A step-by-step build & test guide is in [`USAGE.md`](USAGE.md).

---

## 1. Executive summary

| # | Vulnerability | Severity | Impact | Status |
|---|---------------|----------|--------|--------|
| 1 | Master identity key leaks through `blindedSign` (constant nonce prefix) | **CRITICAL** | Full onion identity recovery from a **single public descriptor** | Fixed |
| 2 | `RegisterDescriptor` accepts forged instance descriptors (no signature / binding verification) | **CRITICAL** | Traffic hijack of any GoBalance frontend | Fixed |
| 3 | Deterministic, time-seeded RNG path in `pkg/brand` | HIGH (footgun) | Predictable key material for anything that uses it | Removed |
| 4 | Introduction-point shuffle uses `math/rand` | LOW | Weak randomness in protocol-adjacent code | Replaced with `crypto/rand` |

### Vulnerability #1 — master key recovery from one public descriptor (CRITICAL)

The dispatcher `blindedSign()` in `pkg/stem/descriptor/hidden_service.go` passed
`identityKey.Seed()` — the raw 32-byte scalar `a` — into
`BlindedSignWithTorKey()`. Tor-format keys are **extended keys**: 64 bytes
`(a || h)`, where `h` is the PRF key that derives the per-signature nonce
prefix. With `h` missing, the nonce derivation input was empty and

```
kPrime = SHA512("Derive temporary signing key hash input" || <empty>)
```

became a **public constant**. Consequence: anyone who can read ONE published
descriptor can recompute the nonce `r`, solve for the blinded scalar
`s' = (S − r) · H(R‖PK‖M)⁻¹ mod L`, and unblind it with a public multiplier —
recovering the master identity key of the onion service. No server access, no
MitM, no brute force. This is a silent domain-takeover primitive and is
consistent with the mechanism observed in the recent forum hijacks.

**Fix:** the dispatcher now forwards the full extended key
(`gobpk.PrivateKey.PrivKey()`); `BlindedSignWithTorKey` panics on any key that
is not exactly 64 bytes; `blindedSignP2` independently enforces the ESK length
as defence in depth; `gobpk.New` rejects truncated Tor keys at load time.

### Vulnerability #2 — forged instance descriptors accepted (CRITICAL)

`NewReceivedDescriptor()` parsed and *trusted* whatever the network handed it.
Because subcredentials are derived from the blinded key carried **inside the
descriptor itself**, an attacker could mint cryptographically self-consistent
descriptors for someone else's onion address using their own keys. The
frontend would then republish the attacker's introduction points under the
victim's identity — a complete traffic hijack that requires no key recovery
at all.

**Fix:** three-layer verification in the new
`VerifyHiddenServiceDescriptorV3()`: (1) certificate signature under the
blinded key, (2) descriptor signature under the certified signing key, and
(3) **binding** — the blinded key must equal the value the frontend computes
independently from consensus (`GetBlindingParam` + time period) and the
instance address. `RegisterDescriptor` is fail-closed: without a live
consensus it refuses to register rather than trust blindly.

## 2. What's in this package

```
gobalance-patch/
├── README.md                  ← this file (English)
├── usage.md                   ← step-by-step build & test guide (English)
├── README_ID.md               ← ringkasan patch (Bahasa Indonesia)
├── gobalance-security.patch   ← unified diff against master@bb1b0f3 (7 files, +360/−94)
└── gobalance-patched/         ← full pre-patched source tree (drop-in)
    ├── go.mod / go.sum / main.go
    ├── pkg/…                  ← patched libraries, incl. regression tests
    └── poc/                   ← end-to-end attack demo + vulnerable code snapshot
```

## 3. Quick start

```bash
# Option A — patch a fresh upstream checkout
git clone https://gitlab.com/n0tr1v/gobalance && cd gobalance
git apply /path/to/gobalance-security.patch
go build ./... && go test ./...

# Option B — use the bundled pre-patched tree (fastest)
cd gobalance-patched
go build ./...
go test ./poc/ -v      # attack demo: succeeds vs vulnerable snapshot, fails vs patch
go test ./...          # full suite: 8 packages ok
```

See [`USAGE.md`](USAGE.md) for the full walkthrough with expected output.

## 4. What the PoC proves

1. **Attack (vulnerable code):** the master scalar is recovered from a single
   public descriptor, and a signature for a *future* time period forged with
   the recovered key is **byte-for-byte identical** to the victim's real
   signature — `Test01_Vulnerable_MasterKeyRecoveredFromSingleDescriptor`.
2. **Defense:** the patched build rejects the truncated 32-byte Tor key with
   an explicit panic naming the risk —
   `Test02_Patched_TruncatedTorKeyRejected`.
3. **Compatibility:** patched tor-path signatures still verify as standard
   ed25519 under the blinded public key, so Tor interoperability is
   unchanged — `Test03_Patched_TorPathSignaturesVerifyAsStdEd25519`.
4. **Defense:** replaying the same attack math against patched code yields
   garbage that no longer matches the true master scalar —
   `Test04_Patched_AttackMathYieldsGarbage`.
5. **Defense (#2):** a self-consistent forged descriptor passes the old trust
   model's checks (parse + cert-sig + descriptor-sig) but is rejected by the
   new consensus binding check —
   `TestForgedSelfConsistentDescriptorIsDetected`.
6. **Defense (#2):** the real intake path accepts honest descriptors and
   rejects tampered / mis-bound ones —
   `TestNewReceivedDescriptor_AcceptsHonestDescriptor`,
   `_RejectsTamperedSignature`, `_RejectsWrongIdentityBinding`.

All keys in the PoC are generated locally at test time. **No real services
were targeted.**

## 5. Operational notes — read before deploying

1. **Rotate keys if you ever ran the vulnerable code.** One public descriptor
   was enough to recover the master key (vuln #1). The patch closes the leak
   going forward but cannot un-publish descriptors that were already public.
   Create a new onion identity and migrate.
2. **Wire compatibility is preserved.** Descriptor formats are unchanged and
   signatures remain standard ed25519 under the blinded key — Tor and normal
   verifiers see no difference. Seed/PEM-format keys behave exactly as before
   (that path was always correct; the original `TestBlindedSign` still
   passes).
3. **Fail-closed behavior is intentional.** Without a live consensus the
   frontend now refuses to register instance descriptors instead of trusting
   them blindly.
4. **The upstream `patch1` branch does not fix vuln #1 or #2.** This patch
   must be applied on top of master (or use the bundled tree).

## 6. Test environment

- Go 1.21.13, linux/amd64 (`go.mod` declares `go 1.18`).
- `go vet ./...` clean; `go build ./...` OK.
- `go test ./...` → 8 packages `ok`, 0 failures, no regressions (including
  the pre-existing upstream tests).
