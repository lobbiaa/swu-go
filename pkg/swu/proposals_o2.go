package swu

import "github.com/1239t/swu-go/pkg/ikev2"

// CreateO2GermanyProposal creates a single proposal specifically for O2 Germany ePDG
// Based on successful packet capture analysis
func CreateO2GermanyProposal() []*ikev2.Proposal {
	prop := ikev2.NewProposal(1, ikev2.ProtoIKE, nil)

	// Encryption: AES-CBC-256
	prop.AddTransform(ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 256)

	// Integrity: AUTH_HMAC_SHA2_256_128
	prop.AddTransform(ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA2_256_128, 0)

	// PRF: PRF_HMAC_SHA1 (critical!)
	prop.AddTransform(ikev2.TransformTypePRF, ikev2.PRF_HMAC_SHA1, 0)

	// Key Exchange: 2048 bit MODP group (14)
	prop.AddTransform(ikev2.TransformTypeDH, ikev2.MODP_2048_bit, 0)

	return []*ikev2.Proposal{prop}
}
