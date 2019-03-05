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

	"pault.ag/go/othername"
	"pault.ag/go/othername/fasc"
)

// Extension of the built-in crypto/x509.Certificate type. This contains the
// Certificate as an anonymous member of the piv.Certificate struct.
//
// Additionally, it contains the extractions for the PIV peculiar OID values,
// such as the Microsoft UPN (used for smartcard login), FASCs and if the
// cardholder has a completed NACI.
type Certificate struct {
	*x509.Certificate

	// This field is a largely unreliable and poor indicator of the cardholder's
	// level of vetting -- it merely asserts as to if the cardholder has a
	// completed NACI at the time of card issue. If the cardholder has other
	// (sometimes supersets!) of the NACI, this may not be true.
	//
	// Additionally, not all agencies set this extension, and it's not widely
	// used enough to be considered accurate. It's being parsed for any legacy
	// uses of this extension.
	CompletedNACI *bool

	// UPN or the Universal Principal Name is a email-like key that can be used
	// by the operating system or directory server to determine which account to
	// grant this smartcard access to.
	//
	// These are *not* valid Emails. For the cardholder's email, access the
	// standard x509.EmailAddresses SAN.
	PricipalNames []string

	// FASC, or Federal Agency Smartcard Number, is a legacy field that was
	// used to enable building access control systems. It's largely not used
	// but still written to new Certificates.
	FASCs []fasc.FASC
}

// Create a piv.Certificate from a standard crypto/x509.Certificate, parsing
// the various PIV peculiar fields.
func NewCertificate(cert *x509.Certificate) (*Certificate, error) {
	ret := Certificate{Certificate: cert}
	var err error

	ret.CompletedNACI = HasNACI(cert)

	ret.PricipalNames, err = othername.UPNs(cert)
	if err != nil {
		return nil, err
	}
	ret.FASCs, err = othername.FASCs(cert)
	if err != nil {
		return nil, err
	}

	return &ret, nil
}

// vim: foldmethod=marker
