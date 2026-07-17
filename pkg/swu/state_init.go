//go:build linux

package swu

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"time"

	//"encoding/hex"
	"errors"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
)

func detectOutboundIPv4(remoteIP net.IP, remotePort uint16) (net.IP, error) {
	if remoteIP == nil {
		return nil, errors.New("remote ip is nil")
	}
	r := &net.UDPAddr{IP: remoteIP, Port: int(remotePort)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "udp", r.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if v4 := ua.IP.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, errors.New("cannot detect outbound ip")
}

func (s *Session) sendIKESAInit() error {
	data, err := s.buildIKESAInitPacket()
	if err != nil {
		return err
	}
	return s.socket.SendIKE(data)
}

func (s *Session) buildIKESAInitPacket() ([]byte, error) {
	fmt.Printf("[O2-DEBUG] buildIKESAInitPacket: cfg.MCC=%s cfg.MNC=%s cfg.IKEProposals=%d\n",
		s.cfg.MCC, s.cfg.MNC, len(s.cfg.IKEProposals))

	if len(s.ni) == 0 {
		s.ni = make([]byte, 32)
		rand.Read(s.ni)
	}

	// Determine DH group: use cfg.IKEProposals when set, otherwise hardcoded carrier detection
	var useO2Modp1024 bool

	if len(s.cfg.IKEProposals) > 0 {
		fmt.Printf("[O2-DEBUG] cfg.IKEProposals is set, count=%d, checking for modp1024\n",
			len(s.cfg.IKEProposals))

		for _, p := range s.cfg.IKEProposals {
			if strings.Contains(p, "modp1024") {
				useO2Modp1024 = true
				fmt.Printf("[O2-DEBUG] Found modp1024 in cfg.IKEProposals: %s\n", p)
				break
			}
		}
	} else {
		// Legacy hardcoded carrier detection (fallback)
		useO2Modp1024 = s.cfg.MCC == "262" && (s.cfg.MNC == "03" || s.cfg.MNC == "003")
		fmt.Printf("[O2-DEBUG] Using legacy carrier check: mcc=%s mnc=%s isO2Germany=%v\n",
			s.cfg.MCC, s.cfg.MNC, useO2Modp1024)
	}

	dhGroup := uint16(14) // Default: modp2048
	dhGroupType := ikev2.MODP_2048_bit

	if useO2Modp1024 {
		dhGroup = 2
		dhGroupType = ikev2.MODP_1024_bit
		fmt.Printf("[O2-DEBUG] Using modp1024 for O2 Germany, dhGroup=%d\n", dhGroup)
	}

	if s.DH == nil {
		var err error
		s.DH, err = crypto.NewDiffieHellman(dhGroup)
		if err != nil {
			return nil, err
		}
		if err := s.DH.GenerateKey(); err != nil {
			return nil, err
		}
	}

	var proposals []*ikev2.Proposal
	if useO2Modp1024 {
		proposals = ikev2.CreateO2GermanyProposalsIKE(nil)
		fmt.Printf("[O2-DEBUG] Using O2 Germany proposals, count=%d dhGroup=%d\n", len(proposals), dhGroup)
	} else {
		proposals = ikev2.CreateMultiProposalIKE(nil)
		fmt.Printf("[O2-DEBUG] Using default multi-proposals, count=%d dhGroup=%d\n", len(proposals), dhGroup)
	}

	saPayload := &ikev2.EncryptedPayloadSA{
		Proposals: proposals,
	}

	kePayload := &ikev2.EncryptedPayloadKE{
		DHGroup: dhGroupType,
		KEData:  s.DH.PublicKeyBytes(),
	}

	noncePayload := &ikev2.EncryptedPayloadNonce{
		NonceData: s.ni,
	}

	localPort := s.cfg.LocalPort
	if localPort == 0 {
		if lp, ok := s.socket.(interface{ LocalPort() uint16 }); ok {
			localPort = lp.LocalPort()
		}
	}
	remoteIP := net.ParseIP(s.cfg.EpDGAddr).To4()
	remotePort := s.cfg.EpDGPort
	if remotePort == 0 {
		remotePort = 500
	}

	if ep, ok := s.socket.(interface {
		LocalIP() net.IP
		RemoteIP() net.IP
		RemotePort() int
	}); ok {
		if rip := ep.RemoteIP(); rip != nil {
			if v4 := rip.To4(); v4 != nil {
				remoteIP = v4
			}
		}
		if rp := ep.RemotePort(); rp != 0 {
			remotePort = uint16(rp)
		}
	}

	localIP := net.ParseIP(s.cfg.LocalAddr).To4()
	if ep, ok := s.socket.(interface{ LocalIP() net.IP }); ok {
		if lip := ep.LocalIP(); lip != nil {
			if v4 := lip.To4(); v4 != nil && !v4.Equal(net.IPv4zero) {
				localIP = v4
			}
		}
	}
	if localIP == nil || localIP.Equal(net.IPv4zero) {
		if remoteIP != nil {
			if out, err := detectOutboundIPv4(remoteIP, remotePort); err == nil && out != nil {
				localIP = out
			}
		}
	}

	srcHash := ikev2.CalculateNATDetectionHash(s.SPIi, 0, localIP, localPort)
	natSrcPayload := ikev2.CreateNATDetectionNotify(ikev2.NAT_DETECTION_SOURCE_IP, srcHash)

	dstHash := ikev2.CalculateNATDetectionHash(s.SPIi, 0, remoteIP, remotePort)
	natDstPayload := ikev2.CreateNATDetectionNotify(ikev2.NAT_DETECTION_DESTINATION_IP, dstHash)

	fragNotify := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.IKEV2_FRAGMENTATION_SUPPORTED,
	}

	payloads := []ikev2.Payload{saPayload, kePayload, noncePayload, fragNotify}
	if s.sendCookie && len(s.cookie) > 0 {
		payloads = append(payloads, &ikev2.EncryptedPayloadNotify{
			ProtocolID: 0,
			NotifyType: ikev2.COOKIE,
			NotifyData: s.cookie,
		})
	}
	payloads = append(payloads, natSrcPayload, natDstPayload)

	header := &ikev2.IKEHeader{
		SPIi:         s.SPIi,
		SPIr:         [8]byte{},
		NextPayload:  ikev2.SA,
		Version:      0x20,
		ExchangeType: ikev2.IKE_SA_INIT,
		Flags:        ikev2.FlagInitiator,
		MessageID:    0,
	}

	packet, err := ikev2.EncodeIKE(header, payloads)
	if err != nil {
		return nil, err
	}
	return packet, nil
}
