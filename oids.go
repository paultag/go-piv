package piv

import (
	"encoding/asn1"
)

/*

Levels:

NPE = Non-Person-Entity

Medium NPE, Medium NPE-112 and Medium NPE-128;
Medium, Medium-2048, Medium-112 and Medium-128;
Medium Hardware, Medium Hardware-2048, Medium Hardware-112 and Medium Hardware-128;

PIV-Auth and PIV-Auth-2048. (Medium Hardware, but only used for physical)
*/

type TokenClass struct {
	Hardware bool
	Person   bool
}

type Policy struct {
	Name string
	Id   asn1.ObjectIdentifier
}

const (
	// DoDBasic = Policy{
	// 	Name:       "DoDBasic",
	// 	Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 2},
	// 	TokenClass: TokenClass{
	// 	},
	// }

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

	// DoDPIVAuth = Policy{
	// 	Name:       "DoDPIVAuth",
	// 	Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 10},
	// 	TokenClass: TokenClass{},
	// }

	// DoDPIVAuth2048 = Policy{
	// 	Name:       "DoDPIVAuth2048",
	// 	Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 20},
	// 	TokenClass: TokenClass{},
	// }

	// DoDPeerInterop = Policy{
	// 	Name:       "DoDPeerInterop",
	// 	Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 31},
	// 	TokenClass: TokenClass{},
	// }

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
)
