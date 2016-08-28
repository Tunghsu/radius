package radius

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/Tunghsu/radius/eap"
)

var ErrMessageAuthenticatorCheckFail = fmt.Errorf("RADIUS Response-Authenticator verification failed")

const maxPacketLength = 4096 // rfc2058 Page 9 Length

type Packet struct {
	Secret        []byte
	Code          Code
	Identifier    uint8
	Authenticator [16]byte //对应的Request请求里面的Authenticator.
	AVPs          []AVP
}

func (p *Packet) Copy() *Packet {
	outP := &Packet{
		Secret:        p.Secret,
		Code:          p.Code,
		Identifier:    p.Identifier,
		Authenticator: p.Authenticator, //这个应该是拷贝
	}
	outP.AVPs = make([]AVP, len(p.AVPs))
	for i := range p.AVPs {
		outP.AVPs[i] = p.AVPs[i].Copy()
	}
	return outP
}

//此方法保证不修改包的内容
//This method does not modify the contents of the package to ensure
func (p *Packet) Encode() (b []byte, err error) {
	p = p.Copy()
	p.SetAVP(&BinaryAVP{
		Type:  AVPTypeMessageAuthenticator,
		Value: make([]byte, 16),
	})
	if p.Code == CodeAccessRequest {
		_, err := rand.Read(p.Authenticator[:])
		if err != nil {
			return nil, err
		}
	}
	//TODO request的时候重新计算密码
	// When the password request recalculation
	b, err = p.encodeNoHash()
	if err != nil {
		return
	}
	//计算Message-Authenticator这个AVP的值,特殊化处理,Message-Authenticator这个AVP被放在最后面
	//Calculation Message-Authenticator, Message-Authenticator is placed at the rearmost
	hasher := hmac.New(crypto.MD5.New, []byte(p.Secret))
	hasher.Write(b)
	copy(b[len(b)-16:len(b)], hasher.Sum(nil))

	// fix up the authenticator
	// handle request and response stuff.
	// here only handle response part.
	switch p.Code {
	case CodeAccessRequest:
	case CodeAccessAccept, CodeAccessReject, CodeAccessChallenge,
		CodeAccountingRequest, CodeAccountingResponse:
		//rfc2865 page 15 Response Authenticator
		//rfc2866 page 6 Response Authenticator
		//rfc2866 page 6 Request Authenticator
		hasher := crypto.Hash(crypto.MD5).New()
		hasher.Write(b)
		hasher.Write([]byte(p.Secret))
		copy(b[4:20], hasher.Sum(nil)) //返回值再把Authenticator写回去
	default:
		return nil, fmt.Errorf("not handle p.Code %d", p.Code)
	}

	return b, err
}

func (p *Packet) encodeNoHash() (b []byte, err error) {
	b = make([]byte, maxPacketLength)
	b[0] = uint8(p.Code)
	b[1] = uint8(p.Identifier)
	copy(b[4:20], p.Authenticator[:])
	written := 20
	bb := b[20:]
	for i, _ := range p.AVPs {
		bb1, err := p.AVPs[i].Encode()
		if err != nil {
			return nil, err
		}
		written += len(bb1)
		if written > maxPacketLength {
			return nil, fmt.Errorf("[Packet.encodeNoHash] packet too large written[%d]>maxPacketLength[%d]",
				written, maxPacketLength)
		}
		copy(bb, bb1)
		bb = bb[len(bb1):]
	}
	binary.BigEndian.PutUint16(b[2:4], uint16(written))
	return b[:written], nil
}

//get one avp
func (p *Packet) GetAVP(attrType AVPType) AVP {
	for i := range p.AVPs {
		if p.AVPs[i].GetType() == attrType {
			return p.AVPs[i]
		}
	}
	return nil
}

//set one avp,remove all other same type
func (p *Packet) SetAVP(avp AVP) {
	p.DeleteOneType(avp.GetType())
	p.AddAVP(avp)
}

func (p *Packet) AddAVP(avp AVP) {
	p.AVPs = append(p.AVPs, avp)
}

func (p *Packet) GetVsa(typ VendorType) VSA {
	for i := range p.AVPs {
		if p.AVPs[i].GetType() != AVPTypeVendorSpecific {
			continue
		}
		vsa, ok := p.AVPs[i].(*VendorSpecificAVP)
		if !ok {
			continue //允许使用binaryAVP代表一个AVPTypeVendorSpecific
		}
		if vsa.Value.GetType() != typ {
			continue
		}
		return vsa.Value
	}
	return nil
}

//delete all avps with this type
func (p *Packet) DeleteOneType(attrType AVPType) {
	for i := 0; i < len(p.AVPs); i++ {
		if p.AVPs[i].GetType() == attrType {
			for j := i; j < len(p.AVPs)-1; j++ {
				p.AVPs[j] = p.AVPs[j+1]
			}
			p.AVPs = p.AVPs[:len(p.AVPs)-1]
			i--
			break
		}
	}
	return
}

func (p *Packet) Reply() *Packet {
	pac := new(Packet)
	pac.Authenticator = p.Authenticator
	pac.Identifier = p.Identifier
	pac.Secret = p.Secret
	state := p.GetState()
	if len(state) > 0 {
		pac.SetState(state)
	}
	return pac
}

func (p *Packet) Send(c net.PacketConn, addr net.Addr) error {
	buf, err := p.Encode()
	if err != nil {
		return err
	}

	_, err = c.WriteTo(buf, addr)
	return err
}

// 这个只能解密各种Request
func DecodeRequestPacket(Secret []byte, buf []byte) (p *Packet, err error) {
	p = &Packet{Secret: Secret}
	p.Code = Code(buf[0])
	p.Identifier = buf[1]
	copy(p.Authenticator[:], buf[4:20])
	//read attributes
	b := buf[20:]
	for {
		if len(b) == 0 {
			break
		}
		if len(b) < 2 {
			return nil, fmt.Errorf("[radius.DecodePacket] unexcept EOF")
		}
		length := uint8(b[1])
		if int(length) > len(b) {
			return nil, fmt.Errorf("[radius.DecodePacket] invalid avp length len:%d len(b):%d", length, len(b))
		}
		avp, err := avpDecode(p, b[:length])
		if err != nil {
			return nil, err
		}
		p.AVPs = append(p.AVPs, avp)
		b = b[length:]
	}
	//验证Message-Authenticator,并且通过测试验证此处算法是正确的
	//此处不修改Message-Authenticator的值
	err = p.checkMessageAuthenticator()
	if err != nil {
		return p, err
	}
	return p, nil
}

// 解密response包
func DecodeResponsePacket(Secret []byte, buf []byte, RequestAuthenticator [16]byte) (p *Packet, err error) {
	p = &Packet{
		Secret:        Secret,
		Authenticator: RequestAuthenticator,
	}
	p.Code = Code(buf[0])
	p.Identifier = buf[1]
	//read attributes
	b := buf[20:]
	for {
		if len(b) == 0 {
			break
		}
		if len(b) < 2 {
			return nil, fmt.Errorf("[radius.DecodePacket] unexcept EOF")
		}
		length := uint8(b[1])
		if int(length) > len(b) {
			return nil, fmt.Errorf("[radius.DecodePacket] invalid avp length len:%d len(b):%d", length, len(b))
		}
		avp, err := avpDecode(p, b[:length])
		if err != nil {
			return nil, err
		}
		p.AVPs = append(p.AVPs, avp)
		b = b[length:]
	}
	//验证Message-Authenticator,并且通过测试验证此处算法是正确的
	//Verify Message-Authenticator, and tested to verify the algorithm is correct here
	//此处不修改Message-Authenticator的值
	err = p.checkMessageAuthenticator()
	if err != nil {
		return p, err
	}
	return p, nil
}

//如果没有MessageAuthenticator也算通过
//If no Message Authenticator can be considered by
func (p *Packet) checkMessageAuthenticator() (err error) {
	AuthenticatorI := p.GetAVP(AVPTypeMessageAuthenticator)
	if AuthenticatorI == nil {
		return nil
	}
	Authenticator := AuthenticatorI.(*BinaryAVP)
	AuthenticatorValue := Authenticator.Value
	defer func() { Authenticator.Value = AuthenticatorValue }()
	Authenticator.Value = make([]byte, 16)
	content, err := p.encodeNoHash()
	if err != nil {
		return err
	}
	hasher := hmac.New(crypto.MD5.New, []byte(p.Secret))
	hasher.Write(content)
	if !hmac.Equal(hasher.Sum(nil), AuthenticatorValue) {
		return ErrMessageAuthenticatorCheckFail
	}
	return nil
}

func (p *Packet) String() string {
	s := "Code: " + p.Code.String() + "\n" +
		"Identifier: " + strconv.Itoa(int(p.Identifier)) + "\n" +
		"Authenticator: " + fmt.Sprintf("%#v", p.Authenticator) + "\n"
	for _, avp := range p.AVPs {
		s += avp.String() + "\n"
	}
	return s
}

//转成字符串map,便于进行log(序列化?),只有实际信息,已经把加密的东西剔除掉了
func (p *Packet) ToStringMap() map[string]string {
	out := make(map[string]string, len(p.AVPs))
	for _, avp := range p.AVPs {
		if avp.GetType() == AVPTypeMessageAuthenticator {
			continue
		}
		out[avp.GetType().String()] = avp.ValueAsString()
	}
	out["Code"] = p.Code.String()
	out["Identifier"] = strconv.Itoa(int(p.Identifier))
	return out
}

func (p *Packet) GetUsername() (username string) {
	avp := p.GetAVP(AVPTypeUserName)
	if avp == nil {
		return ""
	}
	return avp.(*StringAVP).Value
}
func (p *Packet) GetPassword() (password string) {
	avp := p.GetAVP(AVPTypeUserPassword)
	if avp == nil {
		return ""
	}
	return avp.(*PasswordAVP).Value
}

func (p *Packet) GetNasIpAddress() (ip net.IP) {
	avp := p.GetAVP(AVPTypeNASIPAddress)
	if avp == nil {
		return nil
	}
	return avp.(*IpAVP).Value
}

func (p *Packet) GetAcctStatusType() AcctStatusTypeEnum {
	avp := p.GetAVP(AVPTypeAcctStatusType)
	if avp == nil {
		return AcctStatusTypeEnum(0)
	}
	return avp.(*Uint32EnumAVP).Value.(AcctStatusTypeEnum)
}

func (p *Packet) GetAcctSessionId() string {
	avp := p.GetAVP(AVPTypeAcctSessionId)
	if avp == nil {
		return ""
	}
	return avp.(*StringAVP).Value
}

func (p *Packet) GetAcctTotalOutputOctets() uint64 {
	out := uint64(0)
	avp := p.GetAVP(AVPTypeAcctOutputOctets)
	if avp != nil {
		out += uint64(avp.(*Uint32AVP).Value)
	}
	avp = p.GetAVP(AVPTypeAcctOutputGigawords)
	if avp != nil {
		out += uint64(avp.(*Uint32AVP).Value) * (2 ^ 32)
	}
	return out
}

func (p *Packet) GetAcctTotalInputOctets() uint64 {
	out := uint64(0)
	avp := p.GetAVP(AVPTypeAcctInputOctets)
	if avp != nil {
		out += uint64(avp.(*Uint32AVP).Value)
	}
	avp = p.GetAVP(AVPTypeAcctInputGigawords)
	if avp != nil {
		out += uint64(avp.(*Uint32AVP).Value) * (2 ^ 32)
	}
	return out
}

// it is ike_id in strongswan client
func (p *Packet) GetNASPort() uint32 {
	avp := p.GetAVP(AVPTypeNASPort)
	if avp == nil {
		return 0
	}
	return avp.(*Uint32AVP).Value
}

func (p *Packet) GetNASIdentifier() string {
	avp := p.GetAVP(AVPTypeNASIdentifier)
	if avp == nil {
		return ""
	}
	return avp.(*StringAVP).Value
}

func (p *Packet) GetEAPMessage() eap.Packet {
	avp := p.GetAVP(AVPTypeEAPMessage)
	if avp == nil {
		return nil
	}
	return avp.(*EapAVP).Value
}

func (p *Packet) GetState() []byte {
	avp := p.GetAVP(AVPTypeState)
	if avp == nil {
		return nil
	}
	return avp.GetValue().([]byte)
}

func (p *Packet) SetState(state []byte) {
	p.SetAVP(&BinaryAVP{
		Type:  AVPTypeState,
		Value: state,
	})
}

func (p *Packet) SetAcctInterimInterval(second int) {
	p.SetAVP(&Uint32AVP{
		Type:  AVPTypeAcctInterimInterval,
		Value: uint32(second),
	})
}

func (p *Packet) GetAcctSessionTime() uint32 {
	avp := p.GetAVP(AVPTypeAcctSessionTime)
	if avp == nil {
		return 0
	}
	return avp.GetValue().(uint32)
}
