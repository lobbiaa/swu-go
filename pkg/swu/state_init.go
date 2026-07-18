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
	fmt.Printf("[O2-DEBUG] sendIKESAInit: sending %d bytes via socket\n", len(data))
	err = s.socket.SendIKE(data)
	fmt.Printf("[O2-DEBUG] sendIKESAInit: SendIKE result=%v\n", err)
	return err
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

	packet := ikev2.NewIKEPacket()
	packet.Header = &ikev2.IKEHeader{
		SPIi:         s.SPIi,
		SPIr:         0,
		NextPayload:  ikev2.SA,
		Version:      0x20,
		ExchangeType: ikev2.IKE_SA_INIT,
		Flags:        ikev2.FlagInitiator,
		MessageID:    0,
	}
	packet.Payloads = payloads

	data, err := packet.Encode()
	if err != nil {
		return nil, err
	}

	s.msgBuffer = data
	return data, nil
}

func (s *Session) handleIKESAInitResp(data []byte) error {
	packet, err := ikev2.DecodePacket(data)
	if err != nil {
		return fmt.Errorf("解码 SA_INIT 响应失败: %v", err)
	}

	if packet.Header.ExchangeType != ikev2.IKE_SA_INIT {
		return fmt.Errorf("意外的交换类型: %d", packet.Header.ExchangeType)
	}
	s.SPIr = packet.Header.SPIr

	var saPayload *ikev2.EncryptedPayloadSA
	var kePayload *ikev2.EncryptedPayloadKE
	var noncePayload *ikev2.EncryptedPayloadNonce
	var natSrc []byte
	var natDst []byte

	for _, p := range packet.Payloads {
		switch v := p.(type) {
		case *ikev2.EncryptedPayloadSA:
			saPayload = v
		case *ikev2.EncryptedPayloadKE:
			kePayload = v
		case *ikev2.EncryptedPayloadNonce:
			noncePayload = v
		case *ikev2.EncryptedPayloadNotify:
			if v.NotifyType == ikev2.COOKIE {
				if err := s.handleCookie(v.NotifyData); err != nil {
					return err
				}
				return ErrCookieRequired
			}
			if v.NotifyType == ikev2.NAT_DETECTION_SOURCE_IP {
				natSrc = v.NotifyData
			}
			if v.NotifyType == ikev2.NAT_DETECTION_DESTINATION_IP {
				natDst = v.NotifyData
			}
			if v.NotifyType == ikev2.IKEV2_FRAGMENTATION_SUPPORTED {
				s.fragmentationSupported = true
				s.Logger.Info("ePDG 支持 IKE Fragmentation")
			}
			if v.NotifyType == 14 { // NO_PROPOSAL_CHOSEN
				return errors.New("服务器拒绝了提议 (NO_PROPOSAL_CHOSEN)")
			}
			if v.NotifyType == ikev2.REDIRECT {
				addr, err := ParseRedirectData(v.NotifyData)
				if err != nil {
					s.Logger.Warn("解析 REDIRECT 数据失败", logger.Err(err))
				} else {
					return &RedirectError{NewAddr: addr}
				}
			}
		}
	}

	if saPayload == nil || kePayload == nil || noncePayload == nil {
		return errors.New("SA_INIT 响应中缺少强制性载荷")
	}

	s.nr = noncePayload.NonceData

	if len(natSrc) > 0 && len(natDst) > 0 {
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

		expNatSrc := ikev2.CalculateNATDetectionHash(s.SPIi, s.SPIr, localIP, localPort)
		expNatDst := ikev2.CalculateNATDetectionHash(s.SPIi, s.SPIr, remoteIP, remotePort)

		natDetected := !bytes.Equal(natSrc, expNatSrc) || !bytes.Equal(natDst, expNatDst)
		if natDetected {
			if setter, ok := s.socket.(interface{ SetRemotePort(int) }); ok {
				setter.SetRemotePort(4500)
			}
			s.startNATKeepalive(20 * time.Second)
			s.Logger.Debug("检测到 NAT，切换到 UDP 4500")
		}
	}

	selProp := saPayload.Proposals[0]
	var prfID uint16
	var encrID uint16
	var encrKeyLenBits int
	var integID uint16
	var dhID uint16

	for _, t := range selProp.Transforms {
		switch t.Type {
		case ikev2.TransformTypeEncr:
			encrID = uint16(t.ID)
			for _, a := range t.Attributes {
				if a.Type == ikev2.AttributeKeyLength {
					encrKeyLenBits = int(a.Val)
				}
			}
		case ikev2.TransformTypeInteg:
			integID = uint16(t.ID)
		case ikev2.TransformTypePRF:
			prfID = uint16(t.ID)
		case ikev2.TransformTypeDH:
			dhID = uint16(t.ID)
		}
	}

	s.Logger.Debug("ePDG_SA_INIT: IKE SA 算法协商成功",
		logger.String("encr", ikev2.EncrToString(encrID)),
		logger.Int("encr_key_bits", encrKeyLenBits),
		logger.String("integ", ikev2.IntegToString(integID)),
		logger.String("prf", ikev2.PRFToString(prfID)),
		logger.String("dh", ikev2.DHToString(dhID)),
	)

	s.PRFAlg, err = crypto.GetPRF(prfID)
	if err != nil {
		return fmt.Errorf("选择了不支持的 PRF: %d", prfID)
	}

	s.EncAlg, err = crypto.GetEncrypterWithKeyLen(encrID, encrKeyLenBits)
	if err != nil {
		return fmt.Errorf("选择了不支持的 Encr: %d", encrID)
	}
	s.ikeEncrID = encrID
	s.ikeIsAEAD = encrID == uint16(ikev2.ENCR_AES_GCM_16) || encrID == uint16(ikev2.ENCR_AES_GCM_12) || encrID == uint16(ikev2.ENCR_AES_GCM_8)
	if s.ikeIsAEAD {
		s.ikeIntegID = 0
		s.IntegAlg, _ = crypto.GetIntegrityAlgorithm(0)
	} else {
		s.ikeIntegID = integID
		s.IntegAlg, err = crypto.GetIntegrityAlgorithm(integID)
		if err != nil {
			return fmt.Errorf("选择了不支持的 Integ: %d", integID)
		}
	}

	if _, err := s.DH.ComputeSharedSecret(kePayload.KEData); err != nil {
		return fmt.Errorf("DH 计算失败: %v", err)
	}

	s.Logger.Debug("正在生成密钥材料")
	if err := s.GenerateIKESAKeys(s.nr); err != nil {
		return err
	}

	s.sendCookie = false
	return nil
}

func ParseRedirectData(data []byte) (string, error) {
	if len(data) < 1 {
		return "", errors.New("empty redirect data")
	}
	gwType := data[0]
	gwData := data[1:]

	switch gwType {
	case ikev2.RedirectGWIPv4:
		if len(gwData) != 4 {
			return "", fmt.Errorf("invalid IPv4 length: %d", len(gwData))
		}
		return net.IP(gwData).String(), nil
	case ikev2.RedirectGWIPv6:
		if len(gwData) != 16 {
			return "", fmt.Errorf("invalid IPv6 length: %d", len(gwData))
		}
		return net.IP(gwData).String(), nil
	case ikev2.RedirectGWFQDN:
		return string(gwData), nil
	default:
		return "", fmt.Errorf("unknown gateway identity type: %d", gwType)
	}
}
