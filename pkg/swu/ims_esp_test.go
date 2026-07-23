package swu

import (
	"net"
	"testing"
)

func TestDeriveIMSESPKeys(t *testing.T) {
	// Test vectors from 3GPP TS 33.203 or sample data
	ck := make([]byte, 16)
	ik := make([]byte, 16)
	for i := 0; i < 16; i++ {
		ck[i] = byte(i)
		ik[i] = byte(i + 16)
	}

	tests := []struct {
		name      string
		authAlg   string
		encAlg    string
		wantAuthLen int
		wantEncLen  int
	}{
		{
			name:      "hmac-md5-96 + null",
			authAlg:   "hmac-md5-96",
			encAlg:    "null",
			wantAuthLen: 16,
			wantEncLen:  0,
		},
		{
			name:      "hmac-sha1-96 + aes-cbc",
			authAlg:   "hmac-sha1-96",
			encAlg:    "aes-cbc",
			wantAuthLen: 20,
			wantEncLen:  16,
		},
		{
			name:      "hmac-md5-96 + des-ede3-cbc",
			authAlg:   "hmac-md5-96",
			encAlg:    "des-ede3-cbc",
			wantAuthLen: 16,
			wantEncLen:  24,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authKey, encKey, err := deriveIMSESPKeys(ck, ik, tt.authAlg, tt.encAlg)
			if err != nil {
				t.Fatalf("deriveIMSESPKeys() error = %v", err)
			}
			if len(authKey) != tt.wantAuthLen {
				t.Errorf("authKey length = %d, want %d", len(authKey), tt.wantAuthLen)
			}
			if len(encKey) != tt.wantEncLen {
				t.Errorf("encKey length = %d, want %d", len(encKey), tt.wantEncLen)
			}
			t.Logf("authKey: %x", authKey)
			t.Logf("encKey: %x", encKey)
		})
	}
}

func TestShouldApplyIMSESP(t *testing.T) {
	remoteIP := net.ParseIP("2a02:3018:0:25fc::3")

	s := &Session{
		imsESPPolicy: &IMSESPPolicy{
			RemoteIP:    remoteIP,
			RemotePortS: 6060,
		},
		imsESPRemoteIP:    remoteIP,
		imsESPRemotePortS: 6060,
	}

	// IPv6 TCP packet to 2a02:3018:0:25fc::3:6060
	pkt := make([]byte, 60)
	pkt[0] = 0x60 // IPv6 version
	pkt[6] = 6    // Next header: TCP
	copy(pkt[24:40], remoteIP.To16()) // Destination IP
	pkt[42] = 0x17 // Dst port high byte (6060 = 0x17AC)
	pkt[43] = 0xAC // Dst port low byte

	if !s.shouldApplyIMSESP(pkt) {
		t.Error("shouldApplyIMSESP() = false, want true for matching packet")
	}

	// Non-matching port
	pkt[42] = 0x13 // Port 5060
	pkt[43] = 0xC4
	if s.shouldApplyIMSESP(pkt) {
		t.Error("shouldApplyIMSESP() = true, want false for non-matching port")
	}
}

func TestReplaceIPPayloadWithESP(t *testing.T) {
	s := &Session{}

	// IPv6 TCP packet
	originalPkt := make([]byte, 60)
	originalPkt[0] = 0x60                   // Version 6
	originalPkt[6] = 6                      // Next header: TCP
	originalPkt[4] = 0x00                   // Payload length high
	originalPkt[5] = 0x14                   // Payload length low (20 bytes)
	copy(originalPkt[8:24], net.ParseIP("2a02:303e:8269:7fdd:478c:8f34:cff4:5505").To16())
	copy(originalPkt[24:40], net.ParseIP("2a02:3018:0:25fc::3").To16())

	espPayload := make([]byte, 80)
	for i := range espPayload {
		espPayload[i] = byte(i)
	}

	newPkt, err := s.replaceIPPayloadWithESP(originalPkt, espPayload)
	if err != nil {
		t.Fatalf("replaceIPPayloadWithESP() error = %v", err)
	}

	if len(newPkt) != 40+len(espPayload) {
		t.Errorf("new packet length = %d, want %d", len(newPkt), 40+len(espPayload))
	}

	if newPkt[6] != 50 {
		t.Errorf("next header = %d, want 50 (ESP)", newPkt[6])
	}

	payloadLen := int(newPkt[4])<<8 | int(newPkt[5])
	if payloadLen != len(espPayload) {
		t.Errorf("payload length = %d, want %d", payloadLen, len(espPayload))
	}
}
