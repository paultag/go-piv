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
	"crypto/x509/pkix"
	"encoding/asn1"
)

var (
	oidUID = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
)

// UserIDs returns the User IDs of the cardholder. This may be used by any
// number of applications to map a user account to a cardholder.
func UserIDs(name pkix.Name) []string {
	ret := []string{}

	for _, name := range name.Names {
		if name.Type.Equal(oidUID) {
			uid, ok := name.Value.(string)
			if !ok {
				continue
			}
			ret = append(ret, uid)
		}
	}
	return ret
}

// vim: foldmethod=marker
