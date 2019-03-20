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
	"fmt"

	"encoding/asn1"
)

// This is *not* an LOA number as defined by OMB M04-04
type assuranceLevel uint

var (
	UnknownAssurance     assuranceLevel = 0
	RudimentaryAssurance assuranceLevel = 1
	BasicAssurance       assuranceLevel = 2
	MediumAssurance      assuranceLevel = 3
	HighAssurance        assuranceLevel = 4
)

func (a assuranceLevel) String() string {
	switch a {
	case RudimentaryAssurance:
		return "Rudimentary"
	case BasicAssurance:
		return "Basic"
	case MediumAssurance:
		return "Medium"
	case HighAssurance:
		return "High"
	}
	return "Unknown"
}

// This returns -1 if the LOA this function is bound to is _less_ strict
// than the given LOA, 0 if they're the same, and 1 if the bound LOA
// is _more_ strict than the given LOA.
//
// MediumAssurance.Compare(RudimentaryAssurance) // -1
// MediumAssurance.Compare(HighAssurance)        // 1
// MediumAssurance.Compare(MediumAssurance)      // 0
//
func (a assuranceLevel) Compare(other assuranceLevel) int {
	if a == other {
		return 0
	}
	if a < other {
		return 1
	}
	return -1
}

// Information about the Key that belongs to the issued Certificate.
// This contains information about the type of device that holds the
// key, as well as the subscriber that that it was issued to.
type Issued struct {
	// This is true if the Key is used on a hardware device that does not
	// allow the export of the private key material.
	Hardware bool

	// This is true if the Key is held by a Person, and False if it's held
	// by a Non-Person Entity (NPE).
	Person bool

	// Level of Assurance that the identity of the subscriber is the actual
	// identity in this Certificate.
	AssuranceLevel assuranceLevel
}

// An expression of what CA Policy this Certificate was issued under.
type Policy struct {
	// Name of the Policy for humans to better understand.
	Name string

	// Identifier of the ASN.1 ObjectId of this Policy.
	Id asn1.ObjectIdentifier

	// Information about the key material and subscriber.
	Issued Issued
}

type Policies []Policy

func (p Policies) HighestAssurance() assuranceLevel {
	loa := UnknownAssurance

	for _, el := range p {
		if loa.Compare(el.Issued.AssuranceLevel) > 0 {
			loa = el.Issued.AssuranceLevel
		}
	}

	return loa
}

// Output a human readable string to grok what Policy this is
func (p Policy) String() string {
	return fmt.Sprintf(
		"%s (%s) person=%t hardware=%t loa=%s",
		p.Name,
		p.Id.String(),
		p.Issued.Person,
		p.Issued.Hardware,
		p.Issued.AssuranceLevel,
	)
}

func ParsePolicies(ids []asn1.ObjectIdentifier) Policies {
	ret := Policies{}
	for _, id := range ids {
		policy, ok := allPoliciesMap[id.String()]
		if !ok {
			continue
		}
		ret = append(ret, policy)
	}
	return ret
}

func policyMap(policies Policies) map[string]Policy {
	ret := map[string]Policy{}
	for _, policy := range policies {
		ret[policy.Id.String()] = policy
	}
	return ret
}

// vim: foldmethod=marker
