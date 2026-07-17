package swu

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"time"

	//"encoding/hex"
	"errors"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
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

	// Determine DH group based on carrier
	dhGroup := 14 // Default: modp2048
	dhGroupType := ikev2.MODP_2048_bit

	isO2Germany := s.cfg.MCC == "262" && (s.cfg.MNC == "03" || s.cfg.MNC == "003")
	fmt.Printf("[O2-DEBUG] O2 Germany check: MCC=%s MNC=%s mcc_match=%v mnc_match=%v isO2=%v\n",
		s.cfg.MCC, s.cfg.MNC, s.cfg.MCC == "262", s.cfg.MNC == "03" || s.cfg.MNC == "003", isO2Germany)

	if isO2Germany {
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
	if isO2Germany {
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
		ISPI:   s.SPIi,
		RSPI:   [8]byte{},
		Next:   ikev2.PayloadTypeSA,
		MjVer:  2,
		MnVer:  0,
		Exch:   ikev2.IKE_SA_INIT,
		Flags:  ikev2.FlagInitiator,
		MsgID:  0,
	}

	packet, err := ikev2.EncodeIKE(header, payloads)
	if err != nil {
		return nil, err
	}
	return packet, nil
}
