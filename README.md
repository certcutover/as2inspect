# as2inspect

**Inspect AS2 & X.509 certificates before an expiry stops your EDI traffic.**

Paste or pipe a public certificate and get its **AS2 role** (signing / encryption /
TLS), **expiry urgency**, **SHA-256 fingerprint**, and weak-algorithm warnings.
No signup, no network calls, no private keys.

> Prefer a browser? The same engine runs client-side at **https://certcutover.com**
> — nothing is uploaded.

## Install

```sh
go install github.com/yanzay/as2inspect/cmd/as2inspect@latest
```

Or download a prebuilt binary (macOS, Linux, Windows) from
[Releases](https://github.com/yanzay/as2inspect/releases) and verify against
`checksums.txt`.

## Use

```sh
as2inspect cert.pem                 # inspect one certificate
as2inspect *.pem                    # inspect a whole folder
as2inspect --json cert.pem          # machine-readable output
cat cert.pem | as2inspect -         # read from stdin

# Exits non-zero if any certificate is expired or expiring within 14 days,
# so it doubles as a CI check:
as2inspect partner-certs/*.pem || echo "a certificate needs attention"
```

Example:

```
partner-signing.pem  [WARNING]
  Subject      : CN=Acme AS2,O=Acme Trading Co
  AS2 role     : signing (high)
  Key          : RSA 2048-bit, sig SHA256-RSA
  Expiry       : 39 days remaining
  SHA-256      : E6:D1:65:...
```

## What it reports

- **AS2 role** — signing / encryption / dual-use / endpoint-TLS, from KeyUsage + EKU
- **Urgency** — expired / critical (<14d) / warning (<60d) / plan (<120d) / ok
- **Fingerprints** — SHA-256 & SHA-1 (to confirm a partner imported the right cert)
- **Warnings** — weak signature (SHA-1/MD5), short RSA keys, not-yet-valid

## Safety

Only **public** certificates are accepted. Private keys and PFX/PKCS#12 files are
detected and refused before any parsing happens — the tool never wants your keys.

## License

MIT
