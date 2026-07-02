// Command as2inspect is the free public acquisition wedge for Rollover Ledger:
// inspect AS2/X.509 public certificates from the terminal, no signup, no upload.
//
//	as2inspect cert.pem                 # inspect one certificate
//	as2inspect *.pem                    # inspect a folder of certificates
//	as2inspect --json cert.pem          # machine-readable output
//	cat cert.pem | as2inspect -         # read from stdin
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/yanzay/as2inspect/internal/certs"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	jsonOut := flag.Bool("json", false, "emit JSON instead of a human summary")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "as2inspect — inspect AS2/X.509 public certificates\n\n")
		fmt.Fprintf(os.Stderr, "usage: as2inspect [--json] <cert.pem|cert.der|-> [more...]\n\n")
		fmt.Fprintf(os.Stderr, "Never pass private keys or PFX/PKCS#12 files — they are rejected.\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nInspect certificates in your browser (nothing uploaded): https://certcutover.com\n")
	}
	flag.Parse()

	if *showVer {
		fmt.Printf("as2inspect %s\n", version)
		return
	}

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	now := time.Now()
	var reports []*certs.Report
	exit := 0

	for _, path := range flag.Args() {
		raw, err := readInput(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			exit = 1
			continue
		}
		rep, err := certs.Inspect(raw, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			exit = 1
			continue
		}
		if *jsonOut {
			reports = append(reports, rep)
		} else {
			printHuman(path, rep)
		}
		// Any expired/critical cert makes the tool exit non-zero so it can gate CI.
		if rep.Urgency == certs.UrgencyExpired || rep.Urgency == certs.UrgencyCritical {
			exit = 1
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(reports)
	}
	os.Exit(exit)
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func printHuman(path string, r *certs.Report) {
	badge := map[certs.Urgency]string{
		certs.UrgencyExpired:  "EXPIRED",
		certs.UrgencyCritical: "CRITICAL",
		certs.UrgencyWarning:  "WARNING",
		certs.UrgencyPlan:     "PLAN",
		certs.UrgencyOK:       "OK",
	}[r.Urgency]

	fmt.Printf("\n%s  [%s]\n", path, badge)
	fmt.Printf("  Subject      : %s\n", r.Subject)
	fmt.Printf("  Issuer       : %s%s\n", r.Issuer, selfSignedTag(r.SelfSigned))
	fmt.Printf("  AS2 role     : %s (%s)\n", r.Role, r.RoleConfidence)
	fmt.Printf("  Key          : %s %d-bit, sig %s\n", r.PublicKeyType, r.PublicKeyBits, r.SignatureAlgo)
	fmt.Printf("  Valid        : %s → %s\n", r.NotBefore.Format("2006-01-02"), r.NotAfter.Format("2006-01-02"))
	fmt.Printf("  Expiry       : %s\n", expiryPhrase(r.DaysToExpiry))
	fmt.Printf("  SHA-256      : %s\n", r.SHA256Fingerprint)
	if len(r.DNSNames) > 0 {
		fmt.Printf("  DNS names    : %v\n", r.DNSNames)
	}
	for _, w := range r.Warnings {
		fmt.Printf("  ! %s\n", w)
	}
}

func selfSignedTag(self bool) string {
	if self {
		return "  (self-signed)"
	}
	return ""
}

func expiryPhrase(days int) string {
	switch {
	case days < 0:
		return fmt.Sprintf("expired %d days ago", -days)
	case days == 0:
		return "expires today"
	default:
		return fmt.Sprintf("%d days remaining", days)
	}
}
