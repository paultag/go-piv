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
	"encoding/asn1"
)

var (
	// dodBasic = Policy{
	// 	Name:       "dodBasic",
	// 	ID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 2},
	// 	Issued: Issued{
	// 	},
	// }

	// Medium assurance
	dodMediumNPE = Policy{
		Name:   "dodMediumNPE",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 17},
		Issued: Issued{Person: false, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	dodMediumNPE112 = Policy{
		Name:   "dodMediumNPE112",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 36},
		Issued: Issued{Person: false, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	dodMediumNPE128 = Policy{
		Name:   "dodMediumNPE128",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 37},
		Issued: Issued{Person: false, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	dodMedium = Policy{
		Name:   "dodMedium",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 5},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	dodMedium2048 = Policy{
		Name:   "dodMedium2048",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 18},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	dodMedium112 = Policy{
		Name:   "dodMedium112",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 39},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	dodMedium128 = Policy{
		Name:   "dodMedium128",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 40},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	dodMediumHardware = Policy{
		Name:   "dodMediumHardware",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 9},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	dodMediumHardware2048 = Policy{
		Name:   "dodMediumHardware2048",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 19},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	dodMediumHardware112 = Policy{
		Name:   "dodMediumHardware112",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 42},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	dodMediumHardware128 = Policy{
		Name:   "dodMediumHardware128",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 43},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	dodPIVAuth = Policy{
		Name:   "dodPIVAuth",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 10},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	dodPIVAuth2048 = Policy{
		Name:   "dodPIVAuth2048",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 20},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// dodPeerInterop = Policy{
	// 	Name:       "dodPeerInterop",
	// 	ID:         asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 31},
	// 	Issued: Issued{},
	// }

	dodFORTEZZA = Policy{
		Name:   "dodFORTEZZA",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 4},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: HighAssurance},
	}

	dodType1 = Policy{
		Name:   "dodType1",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 11, 6},
		Issued: Issued{Person: false, Hardware: true, AssuranceLevel: HighAssurance},
	}
)

var (
	// Low risk – authentication, signature or encryption of individual person.
	fbcaRudimentary = Policy{
		Name:   "fbcaRudimentary",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 1},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: RudimentaryAssurance},
	}

	// Low risk – authentication, signature or encryption of individual person.
	fbcaBasic = Policy{
		Name:   "fbcaBasic",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 2},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: BasicAssurance},
	}

	// Medium risk – authentication, signature or encryption of individual
	// person, group, device, or role.
	fbcaMedium = Policy{
		Name:   "fbcaMedium",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 3},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	// Medium risk – authentication, signature or encryption of individual
	// person, group, device, or role where private key is protected on
	// hardware token.
	fbcaMediumHW = Policy{
		Name:   "fbcaMediumHW",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 12},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// Medium risk – authentication, signature or encryption of individual
	// person, group, device, or role.
	fbcaMediumCBP = Policy{
		Name:   "fbcaMediumCBP",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 14},
		Issued: Issued{Person: false, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	// Medium risk – authentication, signature or encryption of individual
	// person, group, or role where private key is protected on hardware token.
	fbcaMediumHWCBP = Policy{
		Name:   "fbcaMediumHWCBP",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 15},
		Issued: Issued{Person: false, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// Medium risk - authentication or encryption of device
	fbcaMediumDevice = Policy{
		Name:   "fbcaMediumDevice",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 37},
		Issued: Issued{Person: false, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	// Medium risk - authentication or encryption of device where private key
	// protected on hardware token.
	fbcaMediumDeviceHW = Policy{
		Name:   "fbcaMediumDeviceHW",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 38},
		Issued: Issued{Person: false, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// High risk – authentication, signature or encryption of USG individual
	// person, group, role, or device where private key protected on hardware
	// token.
	fbcaHigh = Policy{
		Name:   "fbcaHigh",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 4},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: HighAssurance},
	}

	// Medium risk – authentication, signature or encryption of individual
	// person where private key is protected on APL approved smartcard and
	// requires biometric on card.
	fbcaPIVIHW = Policy{
		Name:   "fbcaPIVIHW",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 18},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// Shows possession of PIV-I card w/o PIN use.
	fbcaPIVICardAuth = Policy{
		Name:   "fbcaPIVICardAuth",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 19},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// Signs security objects on PIV-I card.
	fbcaPIVIContentSigning = Policy{
		Name:   "fbcaPIVIContentSigning",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 20},
		Issued: Issued{Person: false, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// All of the SHA policies aren't added because SHA isn't trusted anymore,
	// so assertions of policy are basically uninteresting.

	// // Medium risk – authentication, signature or encryption of individual
	// // person, group, device, or role. (sHA1)
	// sHA1mediumCBP = Policy{
	// 	Name:   "sHA1mediumCBP",
	// 	ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 21},
	// 	Issued: Issued{},
	// }

	// // Medium risk – authentication, signature or encryption of individual
	// // person, group, or role where private key is protected on hardware token.
	// // (sHA1)
	// sHA1mediumHWCBP = Policy{
	// 	Name:   "sHA1mediumHWCBP",
	// 	ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 22},
	// 	Issued: Issued{},
	// }

	// // Medium risk – authentication, signature or encryption of individual
	// // person, group, device, or role. (sHA1)
	// sHA1medium = Policy{
	// 	Name:   "sHA1medium",
	// 	ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 23},
	// 	Issued: Issued{},
	// }

	// // Medium risk – authentication, signature or encryption of individual
	// // person, group, or role where private key is protected on hardware token.
	// // (sHA1)
	// sHA1mediumHW = Policy{
	// 	Name:   "sHA1mediumHW",
	// 	ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 24},
	// 	Issued: Issued{},
	// }

	// // Medium risk - authentication or encryption of device .(sHA1)
	// sHA1devices = Policy{
	// 	Name:   "sHA1devices",
	// 	ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 25},
	// 	Issued: Issued{},
	// }

	// Medium risk – authentication, signature or encryption of USG individual
	// person, group, device, or role.
	commonPolicy = Policy{
		Name:   "commonPolicy",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 6},
		Issued: Issued{Person: true, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	// High risk – authentication, signature or encryption of USG individual
	// person, group, role, or device where private key is protected on
	// hardware token.
	commonHW = Policy{
		Name:   "commonHW",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 7},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// Medium risk – USG authentication or encryption of device.
	commonDevices = Policy{
		Name:   "commonDevices",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 8},
		Issued: Issued{Person: false, Hardware: false, AssuranceLevel: MediumAssurance},
	}

	// Medium risk - authentication or encryption of USG device where private
	// key protected on hardware token.
	commonDevicesHW = Policy{
		Name:   "commonDevicesHW",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 36},
		Issued: Issued{Person: false, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// High risk - Shows possession of PIV card with PIN use
	commonAuth = Policy{
		Name:   "commonAuth",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 13},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// High risk – authentication, signature or encryption of USG individual
	// person, group, role, or device where private key is protected on
	// hardware token.
	commonHigh = Policy{
		Name:   "commonHigh",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 16},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: HighAssurance},
	}

	// Shows possession of PIV card w/o PIN use.
	commoncardAuth = Policy{
		Name:   "commonCardAuth",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 17},
		Issued: Issued{Person: true, Hardware: true, AssuranceLevel: MediumAssurance},
	}

	// Signs security objects on PIV or Derived PIV.
	commonPIVContentSigning = Policy{
		Name:   "commonPIVContentSigning",
		ID:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 39},
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

// vim: foldmethod=marker
