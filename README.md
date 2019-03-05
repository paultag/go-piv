go-piv
======

[![GoDoc](https://godoc.org/pault.ag/go/piv?status.svg)](https://godoc.org/pault.ag/go/piv)

This library has a small set of PIV peculiar extensions to a standard x.509
Certificate. This will parse out Subject Alternative Names common to PIV
Certificates, as well as any custom Extensions.

This is to be used in conjunction with a `crypto/x509.Certificate`, and the
`piv.Certificate` embeds an `crypto/x509.Certificate` as an anonymous
member.

What's PIV?
-----------

PIV Cards are cards defined by FIPS 201, a Federal US Government standard
defining the ID cards employees use. At its core, it's a set of x509
Certificates and corresponding private keys in a configuration that is
standardized across implementations.

For more details on how PIV Tokens can be used, the FICAM
(Federal Identity, Credential, and Access Management) team at GSA
(General Services Administration) has published some guides on GitHub
under [GSA/piv-guides](https://github.com/GSA/piv-guides)
