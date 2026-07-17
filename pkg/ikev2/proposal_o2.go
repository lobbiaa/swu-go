package ikev2

// CreateO2GermanyProposalsIKE creates IKE proposals specifically for O2 Germany
// O2 Germany only accepts modp1024 (DH Group 2)
func CreateO2GermanyProposalsIKE(spi []byte) []*Proposal {
	proposals := []*Proposal{}
	pNum := uint8(1)

	// Proposal 1: O2 preferred (AES-256 + SHA256 + SHA1-PRF + modp1024)
	prop1 := NewProposal(pNum, ProtoIKE, spi)
	prop1.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 256)
	prop1.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0)
	prop1.AddTransform(TransformTypePRF, PRF_HMAC_SHA1, 0)
	prop1.AddTransform(TransformTypeDH, MODP_1024_bit, 0)
	proposals = append(proposals, prop1)
	pNum++

	// Proposal 2: Fallback (AES-128 + SHA256 + SHA1-PRF + modp1024)
	prop2 := NewProposal(pNum, ProtoIKE, spi)
	prop2.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 128)
	prop2.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA2_256_128, 0)
	prop2.AddTransform(TransformTypePRF, PRF_HMAC_SHA1, 0)
	prop2.AddTransform(TransformTypeDH, MODP_1024_bit, 0)
	proposals = append(proposals, prop2)
	pNum++

	// Proposal 3: Legacy compatibility (AES-128 + SHA1 + SHA1-PRF + modp1024)
	prop3 := NewProposal(pNum, ProtoIKE, spi)
	prop3.AddTransformWithKeyLen(TransformTypeEncr, ENCR_AES_CBC, 128)
	prop3.AddTransform(TransformTypeInteg, AUTH_HMAC_SHA1_96, 0)
	prop3.AddTransform(TransformTypePRF, PRF_HMAC_SHA1, 0)
	prop3.AddTransform(TransformTypeDH, MODP_1024_bit, 0)
	proposals = append(proposals, prop3)

	return proposals
}
