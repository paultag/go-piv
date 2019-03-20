package piv

import (
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

const (
	// DoDBasic = Policy{
	// 	Name:       "DoDBasic",
	// 	Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 2},
	// 	TokenClass: TokenClass{
	// 	},
	// }

	// Medium assurance
	DoDMediumNPE = Policy{
		Name:       "DoDMediumNPE",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 17},
		TokenClass: TokenClass{Person: false, Hardware: false},
	}

	DoDMediumNPE112 = Policy{
		Name:       "DoDMediumNPE112",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 36},
		TokenClass: TokenClass{Person: false, Hardware: false},
	}

	DoDMediumNPE128 = Policy{
		Name:       "DoDMediumNPE128",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 37},
		TokenClass: TokenClass{Person: false, Hardware: false},
	}

	DoDMedium = Policy{
		Name:       "DoDMedium",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 5},
		TokenClass: TokenClass{Person: true, Hardware: false},
	}

	DoDMedium2048 = Policy{
		Name:       "DoDMedium2048",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 18},
		TokenClass: TokenClass{Person: true, Hardware: false},
	}

	DoDMedium112 = Policy{
		Name:       "DoDMedium112",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 39},
		TokenClass: TokenClass{Person: true, Hardware: false},
	}

	DoDMedium128 = Policy{
		Name:       "DoDMedium128",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 40},
		TokenClass: TokenClass{Person: true, Hardware: false},
	}

	DoDMediumHardware = Policy{
		Name:       "DoDMediumHardware",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 9},
		TokenClass: TokenClass{Person: true, Hardware: true},
	}

	DoDMediumHardware2048 = Policy{
		Name:       "DoDMediumHardware2048",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 19},
		TokenClass: TokenClass{Person: true, Hardware: true},
	}

	DoDMediumHardware112 = Policy{
		Name:       "DoDMediumHardware112",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 42},
		TokenClass: TokenClass{Person: true, Hardware: true},
	}

	DoDMediumHardware128 = Policy{
		Name:       "DoDMediumHardware128",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 43},
		TokenClass: TokenClass{Person: true, Hardware: true},
	}

	DoDPIVAuth = Policy{
		Name:       "DoDPIVAuth",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 10},
		TokenClass: TokenClass{Person: true, Hardware: true},
	}

	DoDPIVAuth2048 = Policy{
		Name:       "DoDPIVAuth2048",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 20},
		TokenClass: TokenClass{Person: true, Hardware: true},
	}

	// DoDPeerInterop = Policy{
	// 	Name:       "DoDPeerInterop",
	// 	Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 31},
	// 	TokenClass: TokenClass{},
	// }

	DoDFORTEZZA = Policy{
		Name:       "DoDFORTEZZA",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 4},
		TokenClass: TokenClass{Person: true, Hardware: true},
	}

	DoDType1 = Policy{
		Name:       "DoDType1",
		Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 6},
		TokenClass: TokenClass{Person: false, Hardware: true},
	}

	allPolicies []Policy = []Policy{
		DoDMediumNPE, DoDMediumNPE112, DoDMediumNPE128,
		DoDMedium, DoDMedium2048, DoDMedium112, DoDMedium128,
		DoDMediumHardware, DoDMediumHardware2048, DoDMediumHardware112, DoDMediumHardware128,
		DoDPIVAuth, DoDPIVAuth2048,
		DoDFORTEZZA,
		DoDType1,
	}
)
