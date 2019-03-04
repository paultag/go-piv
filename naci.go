package piv

import (
	"crypto/x509"
	"encoding/asn1"
)

var (
	oidNACI = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 9, 1}
)

// Check to see if the PIV Certificate in question has the id-piv-NACI
// ObjectIdentifier, and if so, return the answer to if the NACI has been
// run on the cardholder.
//
// This is sometimes wrong (usually in saying 'no' when someone actually has
// had a NACI), so please ensure this is never used as an authoritative source
// of truth.
func HasNACI(cert *x509.Certificate) *bool {
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(oidNACI) {
			var hasNACI bool
			if _, err := asn1.Unmarshal(extension.Value, &hasNACI); err != nil {
				panic(err)
			}
			return &hasNACI
		}
	}
	return nil
}
