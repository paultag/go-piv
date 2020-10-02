// {{{ Copyright (c) Paul R. Tagliamonte <paultag@gmail.com>, 2019
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE. }}}

package piv

import (
	"crypto/x509"
	"encoding/asn1"
)

var (
	oidNACI = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 9, 1}
)

// HasNACI will check to see if the PIV Certificate in question has the id-piv-NACI
// ObjectIdentifier, and if so, return the answer to if the NACI has been run
// on the cardholder.
//
// This is sometimes wrong (usually in saying 'no' when someone actually has
// had a NACI -- or better than NACI check!), so please ensure this is never
// used as an authoritative source of truth for someone's level of vetting.
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

// vim: foldmethod=marker
