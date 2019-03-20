package piv

import (
	"fmt"

	"encoding/asn1"
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
}

// An expression of what CA Policy this Certificate was issued under.
type Policy struct {
	// Name of the Policy for humans to better understand.
	Name string

	// Identifier of the ASN.1 ObjectId of this Policy.
	Id asn1.ObjectIdentifier

	// Information about the key material and entity that holds it.
	Issued Issued
}

// Output a human readable string to grok what Policy this is
func (p Policy) String() string {
	return fmt.Sprintf(
		"%s (%s) person=%t hardware=%t",
		p.Name,
		p.Id.String(),
		p.Issued.Person,
		p.Issued.Hardware,
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

var (
	// dodBasic = Policy{
	// 	Name:       "dodBasic",
	// 	Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 2},
	// 	Issued: Issued{
	// 	},
	// }

	// Medium assurance
	dodMediumNPE = Policy{
		Name:   "dodMediumNPE",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 17},
		Issued: Issued{Person: false, Hardware: false},
	}

	dodMediumNPE112 = Policy{
		Name:   "dodMediumNPE112",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 36},
		Issued: Issued{Person: false, Hardware: false},
	}

	dodMediumNPE128 = Policy{
		Name:   "dodMediumNPE128",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 37},
		Issued: Issued{Person: false, Hardware: false},
	}

	dodMedium = Policy{
		Name:   "dodMedium",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 5},
		Issued: Issued{Person: true, Hardware: false},
	}

	dodMedium2048 = Policy{
		Name:   "dodMedium2048",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 18},
		Issued: Issued{Person: true, Hardware: false},
	}

	dodMedium112 = Policy{
		Name:   "dodMedium112",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 39},
		Issued: Issued{Person: true, Hardware: false},
	}

	dodMedium128 = Policy{
		Name:   "dodMedium128",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 40},
		Issued: Issued{Person: true, Hardware: false},
	}

	dodMediumHardware = Policy{
		Name:   "dodMediumHardware",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 9},
		Issued: Issued{Person: true, Hardware: true},
	}

	dodMediumHardware2048 = Policy{
		Name:   "dodMediumHardware2048",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 19},
		Issued: Issued{Person: true, Hardware: true},
	}

	dodMediumHardware112 = Policy{
		Name:   "dodMediumHardware112",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 42},
		Issued: Issued{Person: true, Hardware: true},
	}

	dodMediumHardware128 = Policy{
		Name:   "dodMediumHardware128",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 43},
		Issued: Issued{Person: true, Hardware: true},
	}

	dodPIVAuth = Policy{
		Name:   "dodPIVAuth",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 10},
		Issued: Issued{Person: true, Hardware: true},
	}

	dodPIVAuth2048 = Policy{
		Name:   "dodPIVAuth2048",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 20},
		Issued: Issued{Person: true, Hardware: true},
	}

	// dodPeerInterop = Policy{
	// 	Name:       "dodPeerInterop",
	// 	Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 31},
	// 	Issued: Issued{},
	// }

	dodFORTEZZA = Policy{
		Name:   "dodFORTEZZA",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 4},
		Issued: Issued{Person: true, Hardware: true},
	}

	dodType1 = Policy{
		Name:   "dodType1",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 6},
		Issued: Issued{Person: false, Hardware: true},
	}

	allPolicies []Policy = []Policy{
		dodMediumNPE, dodMediumNPE112, dodMediumNPE128,
		dodMedium, dodMedium2048, dodMedium112, dodMedium128,
		dodMediumHardware, dodMediumHardware2048, dodMediumHardware112, dodMediumHardware128,
		dodPIVAuth, dodPIVAuth2048,
		dodFORTEZZA,
		dodType1,
	}

	allPoliciesMap = policyMap(allPolicies)
)
