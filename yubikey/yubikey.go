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

package yubikey

import (
	"pault.ag/go/piv"
	"pault.ag/go/ykpiv"
)

func New(opts ykpiv.Options) (*Yubikey, error) {
	token, err := ykpiv.New(opts)
	if err != nil {
		return nil, err
	}
	yk := Yubikey{token}
	return &yk, nil
}

//
type Yubikey struct {
	*ykpiv.Yubikey
}

func (y Yubikey) getCertificate(slotId ykpiv.SlotId) (*piv.Certificate, error) {
	slot, err := y.Slot(slotId)
	if err != nil {
		return nil, err
	}
	return piv.NewCertificate(slot.Certificate)
}

//
func (y Yubikey) AuthenticationCertificate() (*piv.Certificate, error) {
	return y.getCertificate(ykpiv.Authentication)
}

//
func (y Yubikey) DigitalSignatureCertificate() (*piv.Certificate, error) {
	return y.getCertificate(ykpiv.Signature)
}

//
func (y Yubikey) KeyManagementCertificate() (*piv.Certificate, error) {
	return y.getCertificate(ykpiv.KeyManagement)
}

//
func (y Yubikey) CardAuthenticationCertificate() (*piv.Certificate, error) {
	return y.getCertificate(ykpiv.CardAuthentication)
}

// vim: foldmethod=marker
