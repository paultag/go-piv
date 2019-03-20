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
		Issued: Issued{Person: false, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	dodMediumNPE112 = Policy{
		Name:   "dodMediumNPE112",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 36},
		Issued: Issued{Person: false, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	dodMediumNPE128 = Policy{
		Name:   "dodMediumNPE128",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 37},
		Issued: Issued{Person: false, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	dodMedium = Policy{
		Name:   "dodMedium",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 5},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	dodMedium2048 = Policy{
		Name:   "dodMedium2048",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 18},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	dodMedium112 = Policy{
		Name:   "dodMedium112",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 39},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	dodMedium128 = Policy{
		Name:   "dodMedium128",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 40},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	dodMediumHardware = Policy{
		Name:   "dodMediumHardware",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 9},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	dodMediumHardware2048 = Policy{
		Name:   "dodMediumHardware2048",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 19},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	dodMediumHardware112 = Policy{
		Name:   "dodMediumHardware112",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 42},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	dodMediumHardware128 = Policy{
		Name:   "dodMediumHardware128",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 43},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	dodPIVAuth = Policy{
		Name:   "dodPIVAuth",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 10},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	dodPIVAuth2048 = Policy{
		Name:   "dodPIVAuth2048",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 20},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// dodPeerInterop = Policy{
	// 	Name:       "dodPeerInterop",
	// 	Id:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 31},
	// 	Issued: Issued{},
	// }

	dodFORTEZZA = Policy{
		Name:   "dodFORTEZZA",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 4},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: HighAssurance},
	}

	dodType1 = Policy{
		Name:   "dodType1",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 6},
		Issued: Issued{Person: false, Hardware: true, AssuranceLevel: HighAssurance},
	}
)

var (
	// Low risk – authentication, signature or encryption of individual person.
	fbcaRudimentary = Policy{
		Name:   "fbcaRudimentary",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 1},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: RudimentaryAssurance},
	}

	// Low risk – authentication, signature or encryption of individual person.
	fbcaBasic = Policy{
		Name:   "fbcaBasic",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 2},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: BasicAssurance},
	}

	// Medium risk – authentication, signature or encryption of individual
	// person, group, device, or role.
	fbcaMedium = Policy{
		Name:   "fbcaMedium",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 3},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	// Medium risk – authentication, signature or encryption of individual
	// person, group, device, or role where private key is protected on
	// hardware token.
	fbcaMediumHW = Policy{
		Name:   "fbcaMediumHW",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 12},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// Medium risk – authentication, signature or encryption of individual
	// person, group, device, or role.
	fbcaMediumCBP = Policy{
		Name:   "fbcaMediumCBP",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 14},
		Issued: Issued{Person: false, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	// Medium risk – authentication, signature or encryption of individual
	// person, group, or role where private key is protected on hardware token.
	fbcaMediumHWCBP = Policy{
		Name:   "fbcaMediumHWCBP",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 15},
		Issued: Issued{Person: false, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// Medium risk - authentication or encryption of device
	fbcaMediumDevice = Policy{
		Name:   "fbcaMediumDevice",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 37},
		Issued: Issued{Person: false, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	// Medium risk - authentication or encryption of device where private key
	// protected on hardware token.
	fbcaMediumDeviceHW = Policy{
		Name:   "fbcaMediumDeviceHW",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 38},
		Issued: Issued{Person: false, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// High risk – authentication, signature or encryption of USG individual
	// person, group, role, or device where private key protected on hardware
	// token.
	fbcaHigh = Policy{
		Name:   "fbcaHigh",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 4},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: HighAssurance},
	}

	// Medium risk – authentication, signature or encryption of individual
	// person where private key is protected on APL approved smartcard and
	// requires biometric on card.
	fbcaPIVIHW = Policy{
		Name:   "fbcaPIVIHW",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 18},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// Shows possession of PIV-I card w/o PIN use.
	fbcaPIVICardAuth = Policy{
		Name:   "fbcaPIVICardAuth",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 19},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// Signs security objects on PIV-I card.
	fbcaPIVIContentSigning = Policy{
		Name:   "fbcaPIVIContentSigning",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 20},
		Issued: Issued{Person: false, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// All of the SHA policies aren't added because SHA isn't trusted anymore,
	// so assertions of policy are basically uninteresting.

	// // Medium risk – authentication, signature or encryption of individual
	// // person, group, device, or role. (sHA1)
	// sHA1mediumCBP = Policy{
	// 	Name:   "sHA1mediumCBP",
	// 	Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 21},
	// 	Issued: Issued{},
	// }

	// // Medium risk – authentication, signature or encryption of individual
	// // person, group, or role where private key is protected on hardware token.
	// // (sHA1)
	// sHA1mediumHWCBP = Policy{
	// 	Name:   "sHA1mediumHWCBP",
	// 	Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 22},
	// 	Issued: Issued{},
	// }

	// // Medium risk – authentication, signature or encryption of individual
	// // person, group, device, or role. (sHA1)
	// sHA1medium = Policy{
	// 	Name:   "sHA1medium",
	// 	Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 23},
	// 	Issued: Issued{},
	// }

	// // Medium risk – authentication, signature or encryption of individual
	// // person, group, or role where private key is protected on hardware token.
	// // (sHA1)
	// sHA1mediumHW = Policy{
	// 	Name:   "sHA1mediumHW",
	// 	Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 24},
	// 	Issued: Issued{},
	// }

	// // Medium risk - authentication or encryption of device .(sHA1)
	// sHA1devices = Policy{
	// 	Name:   "sHA1devices",
	// 	Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 25},
	// 	Issued: Issued{},
	// }

	// Medium risk – authentication, signature or encryption of USG individual
	// person, group, device, or role.
	commonPolicy = Policy{
		Name:   "commonPolicy",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 6},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	// High risk – authentication, signature or encryption of USG individual
	// person, group, role, or device where private key is protected on
	// hardware token.
	commonHW = Policy{
		Name:   "commonHW",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 7},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// Medium risk – USG authentication or encryption of device.
	commonDevices = Policy{
		Name:   "commonDevices",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 8},
		Issued: Issued{Person: false, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	// Medium risk - authentication or encryption of USG device where private
	// key protected on hardware token.
	commonDevicesHW = Policy{
		Name:   "commonDevicesHW",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 36},
		Issued: Issued{Person: false, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// High risk - Shows possession of PIV card with PIN use
	commonAuth = Policy{
		Name:   "commonAuth",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 13},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// High risk – authentication, signature or encryption of USG individual
	// person, group, role, or device where private key is protected on
	// hardware token.
	commonHigh = Policy{
		Name:   "commonHigh",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 16},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: HighAssurance},
	}

	// Shows possession of PIV card w/o PIN use.
	commoncardAuth = Policy{
		Name:   "commonCardAuth",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 17},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// Signs security objects on PIV or Derived PIV.
	commonPIVContentSigning = Policy{
		Name:   "commonPIVContentSigning",
		Id:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 39},
		Issued: Issued{Person: false, Hardware: true, AssuranceLevel: MediumAssurance},
	}
)

var (
	allPolicies []Policy = []Policy{
		dodMediumNPE, dodMediumNPE112, dodMediumNPE128,
		dodMedium, dodMedium2048, dodMedium112, dodMedium128,
		dodMediumHardware, dodMediumHardware2048, dodMediumHardware112, dodMediumHardware128,
		dodPIVAuth, dodPIVAuth2048,
		dodFORTEZZA,
		dodType1,

		fbcaRudimentary, fbcaBasic,
		fbcaMedium, fbcaMediumHW,
		fbcaMediumCBP, fbcaMediumHWCBP,
		fbcaMediumDevice, fbcaMediumDeviceHW,
		fbcaHigh, fbcaPIVIHW, fbcaPIVICardAuth, fbcaPIVIContentSigning,
		commonPolicy, commonHW, commonDevices, commonDevicesHW, commonAuth,
		commonHigh, commoncardAuth, commonPIVContentSigning,
	}

	allPoliciesMap = policyMap(allPolicies)
)
