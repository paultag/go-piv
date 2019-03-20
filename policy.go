package piv

import (
	"fmt"

	"encoding/asn1"
)

type assuranceLevel string

var (
	RudimentaryAssurance assuranceLevel = "rudimentary"
	BasicAssurance       assuranceLevel = "basic"
	MediumAssurance      assuranceLevel = "medium"
	HighAssurance        assuranceLevel = "high"
)

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

func Policies(ids []asn1.ObjectIdentifier) []Policy {
	ret := []Policy{}
	for _, id := range ids {
		policy, ok := allPoliciesMap[id.String()]
		if !ok {
			continue
		}
		ret = append(ret, policy)
	}
	return ret
}

func policyMap(policies []Policy) map[string]Policy {
	ret := map[string]Policy{}
	for _, policy := range policies {
		ret[policy.Id.String()] = policy
	}
	return ret
}
