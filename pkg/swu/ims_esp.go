package swu

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ipsec"
)

// IMSESPFlow describes one direction of IMS ipsec-3gpp security association.
type IMSESPFlow struct {
	OutboundSPI uint32
	InboundSPI  uint32
	LocalPort   int
	RemotePort  int
	AuthAlg     string
	EncAlg      string
	AuthKey     []byte
	EncKey      []byte
}

// IMSESPPolicy captures the negotiated IMS ipsec-3gpp parameters from Security-Server header.
type IMSESPPolicy struct {
	RemoteIP    net.IP
	RemotePortC int // P-CSCF port for P-CSCF-initiated connections
	RemotePortS int // P-CSCF port for UE-initiated connections (authenticated REGISTER)
	FlowC       IMSESPFlow
	FlowS       IMSESPFlow
}

// InstallIMSESPPolicy installs IMS ESP policy for double-encapsulation of authenticated SIP traffic.
// Must be called after receiving 401 Unauthorized with Security-Server header.
//
// This is a convenience wrapper that derives IMS ESP keys from CK/IK and installs the policy.
func (s *Session) InstallIMSESPPolicy(remoteIP net.IP, remotePortC, remotePortS int,
	spiC, spiS uint32, authAlg, encAlg string, ck, ik []byte) error {

	if s == nil {
		return fmt.Errorf("swu: session is nil")
	}

	// Derive IMS ESP keys from CK/IK (3GPP TS 33.203)
	authKey, encKey, err := deriveIMSESPKeys(ck, ik, authAlg, encAlg)
	if err != nil {
		return fmt.Errorf("swu: derive IMS ESP keys: %w", err)
	}

	policy := IMSESPPolicy{
		RemoteIP:    remoteIP,
		RemotePortC: remotePortC,
		RemotePortS: remotePortS,
		FlowS: IMSESPFlow{
			OutboundSPI: spiS,
			InboundSPI:  spiC,
			RemotePort:  remotePortS,
			AuthAlg:     authAlg,
			EncAlg:      encAlg,
			AuthKey:     authKey,
			EncKey:      encKey,
		},
	}

	return s.installIMSESPPolicyInternal(policy)
}

// installIMSESPPolicyInternal is the internal implementation
func (s *Session) installIMSESPPolicyInternal(policy IMSESPPolicy) error {
	if s == nil {
		return fmt.Errorf("swu: session is nil")
	}

	s.imsESPMu.Lock()
	defer s.imsESPMu.Unlock()

	// Create outbound SA for FlowS (UE → P-CSCF authenticated REGISTER)
	flowS := policy.FlowS
	encrypter, err := getIMSEncrypter(flowS.EncAlg)
	if err != nil {
		return fmt.Errorf("swu: IMS ESP FlowS encrypter: %w", err)
	}
	integAlg, err := getIMSIntegrity(flowS.AuthAlg)
	if err != nil {
		return fmt.Errorf("swu: IMS ESP FlowS integrity: %w", err)
	}

	saOut := ipsec.NewSecurityAssociationCBC(flowS.OutboundSPI, encrypter, flowS.EncKey, integAlg, flowS.AuthKey)

	s.imsESPPolicy = &policy
	s.imsESPSAOut = saOut
	s.imsESPRemoteIP = append(net.IP(nil), policy.RemoteIP...)
	s.imsESPRemotePortS = policy.RemotePortS

	s.Logger.Info("IMS ESP policy installed",
		logger.String("remote_ip", policy.RemoteIP.String()),
		logger.Int("remote_port_s", policy.RemotePortS),
		logger.Uint32("spi_out", flowS.OutboundSPI),
		logger.String("auth_alg", flowS.AuthAlg),
		logger.String("enc_alg", flowS.EncAlg))

	return nil
}

func getIMSEncrypter(encAlg string) (crypto.Encrypter, error) {
	switch encAlg {
	case "null", "":
		return &nullEncrypter{}, nil
	case "des-ede3-cbc":
		return &tripleDESCBC{}, nil
	case "aes-cbc":
		return crypto.GetEncrypterWithKeyLen(12, 128)
	default:
		return nil, fmt.Errorf("unsupported IMS encryption algorithm %q", encAlg)
	}
}

func getIMSIntegrity(authAlg string) (crypto.IntegrityAlgorithm, error) {
	switch authAlg {
	case "hmac-md5-96":
		return crypto.GetIntegrityAlgorithm(1)
	case "hmac-sha1-96", "hmac-sha-1-96":
		return crypto.GetIntegrityAlgorithm(2)
	case "hmac-sha2-256-128", "hmac-sha-256-128":
		return crypto.GetIntegrityAlgorithm(12)
	default:
		return nil, fmt.Errorf("unsupported IMS auth algorithm %q", authAlg)
	}
}

// nullEncrypter implements no-op encryption (ealg=null)
type nullEncrypter struct{}

func (e *nullEncrypter) Encrypt(plaintext, key, iv, aad []byte) ([]byte, error) {
	return append([]byte(nil), plaintext...), nil
}

func (e *nullEncrypter) Decrypt(ciphertext, key, iv, aad []byte) ([]byte, error) {
	return append([]byte(nil), ciphertext...), nil
}

func (e *nullEncrypter) BlockSize() int { return 1 }
func (e *nullEncrypter) KeySize() int   { return 0 }
func (e *nullEncrypter) IVSize() int    { return 0 }

// tripleDESCBC implements 3DES-CBC encryption
type tripleDESCBC struct{}

func (e *tripleDESCBC) Encrypt(plaintext, key, iv, aad []byte) ([]byte, error) {
	// Placeholder - implement using crypto/des if needed
	return nil, fmt.Errorf("3DES-CBC not yet implemented")
}

func (e *tripleDESCBC) Decrypt(ciphertext, key, iv, aad []byte) ([]byte, error) {
	return nil, fmt.Errorf("3DES-CBC not yet implemented")
}

func (e *tripleDESCBC) BlockSize() int { return 8 }
func (e *tripleDESCBC) KeySize() int   { return 24 }
func (e *tripleDESCBC) IVSize() int    { return 8 }

// Helper to check if a packet matches IMS ESP policy (destined to port-s)
func (s *Session) shouldApplyIMSESP(packet []byte) bool {
	s.imsESPMu.RLock()
	defer s.imsESPMu.RUnlock()

	if s.imsESPPolicy == nil || s.imsESPSAOut == nil {
		return false
	}

	// Parse IP header to extract destination IP and port
	if len(packet) < 40 {
		return false
	}

	ver := packet[0] >> 4
	var dstIP net.IP
	var proto uint8
	var dstPort uint16

	if ver == 4 && len(packet) >= 20 {
		dstIP = net.IP(packet[16:20])
		proto = packet[9]
		if proto == 6 && len(packet) >= 40 { // TCP
			hdrLen := int(packet[0]&0x0f) * 4
			if len(packet) >= hdrLen+4 {
				dstPort = binary.BigEndian.Uint16(packet[hdrLen+2 : hdrLen+4])
			}
		}
	} else if ver == 6 && len(packet) >= 40 {
		dstIP = net.IP(packet[24:40])
		proto = packet[6]
		if proto == 6 && len(packet) >= 44 { // TCP
			dstPort = binary.BigEndian.Uint16(packet[42:44])
		}
	}

	// Match: TCP packet to RemoteIP:RemotePortS (negotiated port-s from 401)
	return proto == 6 &&
		dstIP.Equal(s.imsESPRemoteIP) &&
		int(dstPort) == s.imsESPRemotePortS
}

// replaceIPPayloadWithESP replaces the IP packet's payload with ESP-encapsulated data.
// The IP header is preserved, but the next-header/protocol is changed to ESP (50).
func (s *Session) replaceIPPayloadWithESP(originalPacket []byte, espPayload []byte) ([]byte, error) {
	if len(originalPacket) < 20 {
		return nil, fmt.Errorf("packet too short")
	}

	ver := originalPacket[0] >> 4
	if ver == 4 {
		// IPv4
		if len(originalPacket) < 20 {
			return nil, fmt.Errorf("IPv4 packet too short")
		}
		hdrLen := int(originalPacket[0]&0x0f) * 4
		if len(originalPacket) < hdrLen {
			return nil, fmt.Errorf("invalid IPv4 header length")
		}

		// Build new packet: IP header + ESP payload
		newPacket := make([]byte, hdrLen+len(espPayload))
		copy(newPacket, originalPacket[:hdrLen])

		// Change protocol to ESP (50)
		newPacket[9] = 50

		// Update total length
		totalLen := uint16(hdrLen + len(espPayload))
		binary.BigEndian.PutUint16(newPacket[2:4], totalLen)

		// Copy ESP payload
		copy(newPacket[hdrLen:], espPayload)

		// Recalculate IPv4 header checksum
		newPacket[10] = 0
		newPacket[11] = 0
		checksum := ipv4Checksum(newPacket[:hdrLen])
		binary.BigEndian.PutUint16(newPacket[10:12], checksum)

		return newPacket, nil

	} else if ver == 6 {
		// IPv6
		if len(originalPacket) < 40 {
			return nil, fmt.Errorf("IPv6 packet too short")
		}

		// Build new packet: IPv6 header + ESP payload
		newPacket := make([]byte, 40+len(espPayload))
		copy(newPacket, originalPacket[:40])

		// Change next header to ESP (50)
		newPacket[6] = 50

		// Update payload length
		payloadLen := uint16(len(espPayload))
		binary.BigEndian.PutUint16(newPacket[4:6], payloadLen)

		// Copy ESP payload
		copy(newPacket[40:], espPayload)

		return newPacket, nil
	}

	return nil, fmt.Errorf("unknown IP version %d", ver)
}

// ipv4Checksum calculates the IPv4 header checksum
func ipv4Checksum(header []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// deriveIMSESPKeys derives IMS ESP authentication and encryption keys from CK/IK.
// Per 3GPP TS 33.203 Annex H, the keys are derived using HMAC-SHA-256 with specific labels.
func deriveIMSESPKeys(ck, ik []byte, authAlg, encAlg string) (authKey, encKey []byte, err error) {
	if len(ck) != 16 || len(ik) != 16 {
		return nil, nil, fmt.Errorf("invalid CK/IK length: CK=%d, IK=%d (expected 16 each)", len(ck), len(ik))
	}

	// Concatenate IK || CK as the base key material (per 3GPP TS 33.203)
	ikck := append(append([]byte(nil), ik...), ck...)

	// Derive authentication key
	authKeyLen := getAuthKeyLength(authAlg)
	if authKeyLen > 0 {
		authKey = deriveKey(ikck, []byte("auth"), authKeyLen)
	}

	// Derive encryption key
	encKeyLen := getEncKeyLength(encAlg)
	if encKeyLen > 0 {
		encKey = deriveKey(ikck, []byte("enc"), encKeyLen)
	}

	return authKey, encKey, nil
}

// deriveKey derives a key using HMAC-SHA-256
func deriveKey(baseKey, label []byte, keyLen int) []byte {
	// Simple derivation: HMAC-SHA-256(baseKey, label || counter)
	// For production, use proper KDF like RFC 5869 HKDF
	integ, _ := crypto.GetIntegrityAlgorithm(12) // HMAC-SHA256-128
	input := append(label, 0x01)
	mac := integ.Compute(baseKey, input)
	if len(mac) >= keyLen {
		return mac[:keyLen]
	}
	// If not enough, append more rounds
	result := make([]byte, 0, keyLen)
	result = append(result, mac...)
	counter := byte(0x02)
	for len(result) < keyLen {
		input := append(label, counter)
		mac := integ.Compute(baseKey, input)
		result = append(result, mac...)
		counter++
	}
	return result[:keyLen]
}

func getAuthKeyLength(authAlg string) int {
	switch authAlg {
	case "hmac-md5-96":
		return 16 // MD5 key length
	case "hmac-sha1-96", "hmac-sha-1-96":
		return 20 // SHA-1 key length
	case "hmac-sha2-256-128", "hmac-sha-256-128":
		return 32 // SHA-256 key length
	default:
		return 0
	}
}

func getEncKeyLength(encAlg string) int {
	switch encAlg {
	case "null", "":
		return 0
	case "des-ede3-cbc":
		return 24 // 3DES key length
	case "aes-cbc":
		return 16 // AES-128 key length
	default:
		return 0
	}
}
