package pkcs11

import (
	"fmt"

	"pault.ag/go/cbeff"
	"pault.ag/go/piv"
	"pault.ag/go/piv/biometrics"

	"github.com/miekg/pkcs11"
)

// HSM Configuration object, to define which PKCS#11 .so module to use,
// Certificate and Private Key strings, a PIN (if needed), and the label
// of the token.
type Config struct {
	// Full path to the PKCS#11 object on the filesystem. The exact value
	// of this depends on the host, but should usually end in a .so
	Module string

	// Optional PIN for the PKCS#11 token. If this is nil, no PIN will be
	// sent to the device.
	PIN *string

	//
	TokenLabel string
}

// Create a pkcs11.Attribute array containing constraints that should
// uniquely identify the PKCS#11 Certificate we're interested in
func (c Config) GetDataTemplate(label string) []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
	}
}

// Create a pkcs11.Attribute array containing constraints that should
// uniquely identify the PKCS#11 Certificate we're interested in
func (c Config) GetCertificateTemplate(label string) []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}
}

// Figure out if the TokenInfo we're looking for matches the TokenInfo
// we've got in front of us. This is used to filter out tokens during
// the setup phase.
func (c Config) slotMatchesCriteria(tokenInfo pkcs11.TokenInfo) bool {
	return tokenInfo.Label == c.TokenLabel
}

// Given a pkcs11.Ctx, and a list of slots, figure out which slot is the
// slot we're interested in, returning an error if there's nothing we
// should be using.
func (c Config) SelectSlot(context *pkcs11.Ctx, slots []uint) (uint, error) {
	/* If there's no label matching, and there's only one slot, return
	 * that slot */
	if c.TokenLabel == "" {
		if len(slots) == 1 {
			return slots[0], nil
		}
		// return nil, fmt.Errorf  ???
	}

	for _, slot := range slots {
		token, err := context.GetTokenInfo(slot)
		if err != nil {
			return 0, err
		}
		if c.slotMatchesCriteria(token) {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("No matching slot found")
}

// Method to log out of the Token, and close any open sessions we might
// have open. This method ought to be defer'd after creating a new
// hsm.Store.
func (s Token) Close() error {
	if s.config.PIN != nil {
		if s.context != nil && s.session != nil {
			if err := s.context.Logout(*s.session); err != nil {
				return err
			}
		}
	}

	if s.session != nil {
		return s.context.CloseSession(*s.session)
	}

	if s.context != nil {
		s.context.Destroy()
		if err := s.context.Finalize(); err != nil {
			return err
		}
	}

	return nil
}

// Create a new hsm.Store defined by the hsm.Config. If no slot can be
// found, or the underlying infrastructure throws a problem at us, we will
// return an error.
func New(config Config) (*Token, error) {
	cStore := Token{config: &config}

	cStore.context = pkcs11.New(config.Module)
	if err := cStore.context.Initialize(); err != nil {
		return nil, err
	}

	slots, err := cStore.context.GetSlotList(true)
	if err != nil {
		return nil, err
	}

	slot, err := config.SelectSlot(cStore.context, slots)
	if err != nil {
		return nil, err
	}

	var sessionBitmask uint = pkcs11.CKF_SERIAL_SESSION // | pkcs11.CKF_RW_SESSION
	session, err := cStore.context.OpenSession(slot, sessionBitmask)
	if err != nil {
		return nil, err
	}
	cStore.session = &session

	if config.PIN != nil {
		if err := cStore.context.Login(session, pkcs11.CKU_USER, *config.PIN); err != nil {
			return nil, err
		}
	}

	return &cStore, err
}

// internal hsm.Store encaupsulating state. This implements the store.Store
// interface, as well as crypto.Signer, and crypto.Decryptor.
type Token struct {
	config *Config

	session *pkcs11.SessionHandle
	context *pkcs11.Ctx
}

// Get the object handles that match the set of pkcs11.Attribute critiera
func (s Token) getObjectHandles(template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := s.context.FindObjectsInit(*s.session, template); err != nil {
		return nil, err
	}
	objects := []pkcs11.ObjectHandle{}
	for {
		obj, more, err := s.context.FindObjects(*s.session, 8)
		if err != nil {
			return nil, err
		}
		objects = append(objects, obj...)

		if !more {
			break
		}
	}
	if err := s.context.FindObjectsFinal(*s.session); err != nil {
		return nil, err
	}
	return objects, nil
}

var (
	NotFound = fmt.Errorf("piv: pkcs11: Not Found")
)

// Get the one and only one object that match the set of pkcs11.Attribute
// criteria. If multiple handles are returned, throw an error out,
// and if no objects are returned, throw an error.
func (s Token) getObjectHandle(template []*pkcs11.Attribute) (*pkcs11.ObjectHandle, error) {
	candidates, err := s.getObjectHandles(template)
	if err != nil {
		return nil, err
	}

	if len(candidates) == 0 {
		return nil, NotFound
	} else if len(candidates) != 1 {
		return nil, fmt.Errorf("The query resulted in too many objects.")
	}
	return &candidates[0], nil
}

// Find the object defined by `locate`, and return the attributes returned by
// `attributes`. This is useful for looking up an object that we know is
// unique, and returning the attributes we're interested in.
func (s Token) getAttributes(locate, attributes []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	objectHandle, err := s.getObjectHandle(locate)
	if err != nil {
		return nil, err
	}
	return s.context.GetAttributeValue(*s.session, *objectHandle, attributes)
}

// Find the object defined by `locate`, and return the attribute we're interested
// in, defined by `attribuets`. If multiple handles or multiple attribuets are
// returned, an error will be returned.
func (s Token) getAttribute(locate, attributes []*pkcs11.Attribute) (*pkcs11.Attribute, error) {
	attr, err := s.getAttributes(locate, attributes)
	if err != nil {
		return nil, err
	}

	if len(attr) != 1 {
		return nil, fmt.Errorf("The query resulted in too many attributes.")
	}

	return attr[0], nil
}

// Query the underlying HSM Store for the x509 Certificate we're interested in,
// and return a Go x509.Certificate.
func (s Token) cbeff(label string) (*cbeff.CBEFF, error) {
	dataAttribute, err := s.getAttribute(
		s.config.GetDataTemplate(label),
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)},
	)
	if err != nil {
		return nil, err
	}

	return biometrics.ParseTLVCBEFF(dataAttribute.Value)
}

func (t Token) Facial() (*cbeff.CBEFF, error) {
	return t.cbeff(FacialLabel)
}

// Query the underlying HSM Store for the x509 Certificate we're interested in,
// and return a Go x509.Certificate.
func (s Token) certificate(label string) (*piv.Certificate, error) {
	certAttribute, err := s.getAttribute(
		s.config.GetCertificateTemplate(label),
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)},
	)
	if err != nil {
		return nil, err
	}

	return piv.ParseCertificate(certAttribute.Value)
}

func (t Token) AuthenticationCertificate() (*piv.Certificate, error) {
	return t.certificate(AuthCertificateLabel)
}

func (t Token) DigitalSignatureCertificate() (*piv.Certificate, error) {
	return t.certificate(SignCertificateLabel)
}

func (t Token) KeyManagementCertificate() (*piv.Certificate, error) {
	return t.certificate(KeyManagementCertificateLabel)
}

func (t Token) CardAuthenticationCertificate() (*piv.Certificate, error) {
	return t.certificate(CardAuthCertificateLabel)
}

// vim: foldmethod=marker
