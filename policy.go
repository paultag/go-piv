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

// AssuranceLevel is an enum type defining the levels of assurance.
type AssuranceLevel uint

// This is *not* an LOA number as defined by OMB M04-04
var (
	// UnknownAssurance, as defined by the PIV specs.
	UnknownAssurance AssuranceLevel = 0

	// RudimentaryAssurance, as defined by the PIV specs.
	RudimentaryAssurance AssuranceLevel = 1

	// BasicAssurance, as defined by the PIV specs.
	BasicAssurance AssuranceLevel = 2

	// MediumAssurance, as defined by the PIV specs.
	MediumAssurance AssuranceLevel = 3

	// HighAssurance, as defined by the PIV specs.
	HighAssurance AssuranceLevel = 4
)

// String will return the value as a human readable string.
func (a AssuranceLevel) String() string {
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

// Compare returns -1 if the LOA this function is bound to is _less_ strict
// than the given LOA, 0 if they're the same, and 1 if the bound LOA
// is _more_ strict than the given LOA.
//
// MediumAssurance.Compare(RudimentaryAssurance) // -1
// MediumAssurance.Compare(HighAssurance)        // 1
// MediumAssurance.Compare(MediumAssurance)      // 0
//
func (a AssuranceLevel) Compare(other AssuranceLevel) int {
	if a == other {
		return 0
	}
	if a < other {
		return 1
	}
	return -1
}

// Issued contains information about the Key that belongs to the issued Certificate.
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
	AssuranceLevel AssuranceLevel
}

// Policy is information regarding the level of assurance and a human readable
// name for a specific federal PIV or CAC policy.
type Policy struct {
	// Name of the Policy for humans to better understand.
	Name string

	// Identifier of the ASN.1 ObjectId of this Policy.
	ID asn1.ObjectIdentifier

	// Information about the key material and subscriber.
	Issued Issued
}

// Policies are a set of Policy descriptions.
type Policies []Policy

// HighestAssurance returns the highest assurance level contained within
// the set of policies. This is most useful when looking at the set of policies
// a specific credential was issued under.
func (p Policies) HighestAssurance() AssuranceLevel {
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
		p.ID.String(),
		p.Issued.Person,
		p.Issued.Hardware,
		p.Issued.AssuranceLevel,
	)
}

// ParsePolicies will read a list of ObjectIdentifier objects, and
// return the known Policy objects as a set of Policies.
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
