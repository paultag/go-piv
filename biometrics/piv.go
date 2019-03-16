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

package biometrics // import "pault.ag/go/piv/biometrics"

import (
	"bytes"
	"encoding/asn1"
	"fmt"

	"pault.ag/go/cbeff"
)

// CBEFF, as read from a PIV, is wrapped in an ASN.1 "TLV" structure.
// This will unwrap the data inside the structure, and attempt to parse
// the underlying CBEFF data.
func ParseTLVCBEFF(data []byte) (*CBEFF, error) {
	rv := asn1.RawValue{}
	rest, err := asn1.Unmarshal(data, &rv)
	if err != nil {
		return nil, err
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("cbeff: ASN.1 has trailing data after the CBEFF")
	}

	rvN := asn1.RawValue{}
	_, err = asn1.Unmarshal(rv.Bytes, &rvN)
	if err != nil {
		return nil, err
	}

	return cbeff.Parse(bytes.NewReader(rvN.Bytes))
}

// vim: foldmethod=marker
