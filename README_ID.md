# PATCH & POC KEAMANAN — gobalance

Paket ini berisi patch keamanan lengkap + proof-of-concept untuk repositori
`gitlab.com/n0tr1v/gobalance` (branch `master`, commit `bb1b0f3`),
menindaklanjuti laporan analisis kerentanan terkait insiden take over domain
onion.

---

## 1. Ringkasan

| # | Kerentanan | Severity | Status |
|---|------------|----------|--------|
| 1 | Kebocoran kunci master melalui `blindedSign` (nonce prefix konstan) | **CRITICAL** | Diperbaiki |
| 2 | `RegisterDescriptor` menerima descriptor palsu tanpa verifikasi signature & tanpa binding identitas | **CRITICAL** | Diperbaiki |
| 3 | Jalur RNG deterministik berseed waktu di `pkg/brand` | HIGH (footgun) | Dihilangkan |
| 4 | Shuffle titik introduksi memakai `math/rand` | LOW | Diganti CSPRNG |

**Kerentanan #1 (jalur kunci format Tor).**
Dispatcher `blindedSign()` di `pkg/stem/descriptor/hidden_service.go`
mengirim `identityKey.Seed()` — hanya 32 byte skalar `a` — ke
`BlindedSignWithTorKey()`, padahal kunci format Tor adalah *extended key*
64 byte `(a || h)`; `h` adalah kunci PRF untuk menurunkan prefix nonce
signature. Akibatnya `esk[32:]` kosong dan

```
kPrime = SHA512("Derive temporary signing key hash input" + <kosong>)
```

menjadi **konstanta publik**. Siapa pun yang melihat SATU descriptor publik
dapat menghitung ulang nonce `r`, menyelesaikan
`s' = (S − r) · H(R‖PK‖M)⁻¹ mod L`, lalu unblind dengan multiplier publik —
memulihkan skalar kunci master `(mod L)` yang ekuivalen penuh dengan kunci
identitas onion. Perbaikan: dispatcher meneruskan kunci utuh
(`gobpk.PrivateKey.PrivKey()`), `BlindedSignWithTorKey` menolak (panic) kunci
yang bukan 64 byte, dan `blindedSignP2` menegakkan panjang ESK sebagai
pertahanan berlapis.

**Kerentanan #2 (descriptor instance palsu).**
`NewReceivedDescriptor()` hanya mem-parse dan mendekripsi descriptor yang
diterima dari jaringan. Karena subcredential dihitung dari (kunci publik
identitas, kunci blinded **yang dibawa descriptor itu sendiri**), penyerang
dapat mencetak descriptor yang konsisten secara kriptografis untuk alamat
onion orang lain memakai kunci pilihannya sendiri. Frontend kemudian
menerbitkan ulang titik introduksi penyerang di bawah identitas korban —
pembajakan trafik total tanpa perlu memulihkan kunci apa pun. Perbaikan:
verifikasi tiga lapis di `VerifyHiddenServiceDescriptorV3()` — (1) signature
sertifikat di bawah kunci blinded, (2) signature descriptor di bawah kunci
penandatangan tersertifikasi, (3) **binding**: kunci blinded harus sama
dengan yang dihitung frontend dari konsensus (`GetBlindingParam` + periode
waktu) dan alamat instance — dihitung independen dari isi descriptor.

## 2. Berkas yang diubah / ditambah

Patch inti (7 berkas):
- `pkg/gobpk/gobpk.go` — aksesor `PrivKey()`, invarian panjang kunci Tor di `New()`.
- `pkg/stem/util/ed25519.go` — perbaikan `BlindedSignWithTorKey`, guard seed di `BlindedSign`, guard 64-byte di `blindedSignP2`.
- `pkg/stem/descriptor/hidden_service.go` — dispatcher `blindedSign`, `IdentityKeyFromAddress`, verifikator `VerifyHiddenServiceDescriptorV3`.
- `pkg/onionbalance/descriptor/descriptor.go` — verifikasi di `NewReceivedDescriptor`, shuffle CSPRNG.
- `pkg/onionbalance/instance/instance.go` — `RegisterDescriptor(..., expectedBlindedKeys...)`.
- `pkg/onionbalance/onionbalance/onionbalance.go` — derivasi ekspektasi blinded key dari konsensus sebelum registrasi descriptor.
- `pkg/brand/brand.go` — seluruh jalur deterministik dihapus; hanya `crypto/rand`.

PoC (6 berkas, tidak terhubung ke biner produksi):
- `poc/attack_demo_test.go` — demo serangan end-to-end + pembuktian pertahanan.
- `poc/vulnerable/ed25519_vulnerable.go` — snapshot kode RENTAN dari git history (untuk demo).
- `poc/vulnerable/attack_helpers.go` — helper sisi penyerang untuk demo.
- `pkg/stem/util/attack_poc_test.go` — regresi pertahanan (serangan harus gagal).
- `pkg/stem/descriptor/forged_descriptor_poc_test.go` — descriptor palsu konsisten-diri terdeteksi.
- `pkg/onionbalance/descriptor/verification_poc_test.go` — jalur intake nyata menerima yang jujur, menolak yang dipalsukan.

## 3. Cara menerapkan patch

```bash
# dari root checkout gobalance (master bb1b0f3)
git apply gobalance-security.patch
go build ./... && go test ./...
```

Atau gunakan pohon sumber `gobalance-patched/` yang sudah berisi hasil patch.

## 4. Cara menjalankan PoC

```bash
go test ./poc/ -v            # serangan end-to-end + pembuktian pertahanan
go test ./pkg/stem/... -v    # regresi kripto + descriptor palsu
go test ./...                # seluruh suite (semua lolos, 0 regresi)
```

Bukti hasil (kunci lokal, bukan layanan nyata):

```
Test01_Vulnerable_MasterKeyRecoveredFromSingleDescriptor
    [ATTACK]  master scalar recovered mod L: 03102c50bf57ec9e...
    [TAKEOVER] forged period-2 signature matches the victim's real signature byte-for-byte
Test02_Patched_TruncatedTorKeyRejected
    [DEFENSE] rejected truncated key: ... would publish a constant nonce prefix and leak the master identity key
Test03_Patched_TorPathSignaturesVerifyAsStdEd25519
    [COMPAT]  patched tor-path signatures verify as standard ed25519 under the blinded pubkey
Test04_Patched_AttackMathYieldsGarbage
    [DEFENSE] attacker-recovered value (garbage) ≠ true master scalar
TestForgedSelfConsistentDescriptorIsDetected
    [DEMONSTRATED] self-consistent forged descriptor passes parse + cert-sig + descriptor-sig
    [DEFENSE] binding check rejected the forged descriptor
```

## 5. Catatan operasional penting

1. **Rotasi kunci.** Jika frontend pernah berjalan dengan kode rentan, anggap
   kunci master SUDAH bocor: satu descriptor publik cukup untuk pemulihan
   penuh (kerentanan #1). Patch menutup kebocoran ke depan, tetapi tidak
   bisa menarik kembali descriptor yang sudah terbit. Buat identitas onion
   baru dan migrasikan.
2. **Kompatibilitas.** Signature yang dihasilkan jalur Tor tetap merupakan
   ed25519 standar di bawah kunci blinded — kompatibel dengan Tor dan
   dengan verifikasi normal; tidak ada perubahan format descriptor.
   Sementara itu, kunci format seed/PEM tidak berubah perilakunya.
3. **Fail-closed.** Tanpa konsensus hidup, frontend sekarang menolak
   mendaftarkan descriptor instance (bukan memercayainya buta).
4. **Branch `patch1` upstream tidak menutup kerentanan #1 maupun #2** —
   patch ini harus diterapkan terpisah.
5. `TestBlindedSign` asli tetap lolos: jalur seed memang benar sejak awal;
   guard baru hanya menolak pemakaian yang salah.

## 6. Lingkungan pengujian

- Go 1.21.13 linux/amd64; `go vet ./...` bersih; `go test ./...` 8 paket `ok`.
- Semua kunci dalam PoC dibangkitkan lokal saat pengujian; tidak ada layanan
  nyata yang menjadi target.
