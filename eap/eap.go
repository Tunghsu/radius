package eap

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/Tunghsu/radius/MSCHAPV2"
)

type Code uint8

const (
	CodeRequest  Code = 1
	CodeResponse Code = 2
	CodeSuccess  Code = 3
	CodeFailure  Code = 4
)

func (c Code) String() string {
	switch c {
	case CodeRequest:
		return "Request"
	case CodeResponse:
		return "Response"
	case CodeSuccess:
		return "Success"
	case CodeFailure:
		return "Failure"
	default:
		return "unknow Code " + strconv.Itoa(int(c))
	}
}

type Type uint8

const (
	TypeIdentity         Type = 1
	TypeNotification     Type = 2
	TypeLegacyNak        Type = 3 //Response only
	TypeMd5Challenge     Type = 4
	TypeOneTimePassword  Type = 5 //otp
	TypeGenericTokenCard Type = 6 //gtc
	TypeMSCHAPV2         Type = 26
	TypeExpandedTypes    Type = 254
	TypeExperimentalUse  Type = 255
)

func (c Type) String() string {
	switch c {
	case TypeIdentity:
		return "Identity"
	case TypeNotification:
		return "Notification"
	case TypeLegacyNak:
		return "LegacyNak"
	case TypeMd5Challenge:
		return "Md5Challenge"
	case TypeOneTimePassword:
		return "OneTimePassword"
	case TypeGenericTokenCard:
		return "GenericTokenCard"
	case TypeMSCHAPV2:
		return "MSCHAPV2"
	case TypeExpandedTypes:
		return "ExpandedTypes"
	case TypeExperimentalUse:
		return "ExperimentalUse"
	default:
		return "unknow Type " + strconv.Itoa(int(c))
	}
}

type Packet interface {
	Header() *PacketHeader
	String() string
	Encode() []byte
}

func Decode(b []byte) (p Packet, err error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("[eap.Decode] protocol error input too small 1 len(b)[%d] < 4", len(b))
	}
	code := Code(b[0])
	switch code {
	case CodeRequest, CodeResponse:
		if len(b) < 5 {
			return nil, fmt.Errorf("[eap.Decode] protocol error input too small 1 len(b)[%d] < 5", len(b))
		}
		length := binary.BigEndian.Uint16(b[2:4])
		if len(b) != int(length) {
			return nil, fmt.Errorf("[eap.Decode] protocol error input too small 2 len(b)[%d] != int(length)[%d]", len(b), length)
		}
		h := PacketHeader{
			Code:       Code(b[0]),
			Identifier: uint8(b[1]),
			Type:       Type(b[4]),
		}
		data := b[5:length]
		switch h.Type {
		case TypeIdentity:
			return &IdentityPacket{
				PacketHeader: h,
				Identity:     string(data),
			}, nil
		case TypeMSCHAPV2:
			MSCHAPV2, err := MSCHAPV2.Decode(data)
			if err != nil {
				return nil, err
			}
			return &MSCHAPV2Packet{
				PacketHeader: h,
				MSCHAPV2:     MSCHAPV2,
			}, nil
		case TypeLegacyNak:
			if len(data) == 0 {
				return nil, fmt.Errorf("[eap.Decode] Type: LegacyNak len==0")
			}
			return &LegacyNakPacket{
				PacketHeader:    h,
				DesiredAuthType: Type(data[0]),
			}, nil
		default:
			return nil, fmt.Errorf("[eap.Decode] Type:%s not implement", h.Type)
		}
	case CodeSuccess, CodeFailure:
		return &SimplePacket{
			PacketHeader{
				Code:       Code(b[0]),
				Identifier: uint8(b[1]),
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknow Code " + strconv.Itoa(int(code)))
	}
}

type PacketHeader struct {
	Code       Code
	Identifier uint8
	Type       Type //success and failure do not have any type
}

func (h *PacketHeader) Header() *PacketHeader {
	return h
}

func (h *PacketHeader) String() string {
	switch h.Code {
	case CodeSuccess, CodeFailure:
		return fmt.Sprintf("Code: %s Id:%d", h.Code, h.Identifier)
	default:
		return fmt.Sprintf("Code: %s Id:%d Type:%s", h.Code, h.Identifier, h.Type)
	}
}

func (h *PacketHeader) encode(data []byte) (b []byte) {
	b = make([]byte, len(data)+5)
	b[0] = byte(h.Code)
	b[1] = byte(h.Identifier)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(data)+5))
	b[4] = byte(h.Type)
	copy(b[5:], data)
	return b
}

type IdentityPacket struct {
	PacketHeader
	Identity string
}

func (p *IdentityPacket) String() string {
	return fmt.Sprintf("%s %s", p.PacketHeader.String(), p.Identity)
}

func (p *IdentityPacket) Encode() []byte {
	return p.PacketHeader.encode([]byte(p.Identity))
}

type LegacyNakPacket struct {
	PacketHeader
	DesiredAuthType Type
}

func (p *LegacyNakPacket) String() string {
	return fmt.Sprintf("%s DesiredAuthType:%s", p.PacketHeader.String(), p.DesiredAuthType)
}

func (p *LegacyNakPacket) Encode() []byte {
	return p.PacketHeader.encode([]byte{byte(p.DesiredAuthType)})
}

type MSCHAPV2Packet struct {
	PacketHeader
	MSCHAPV2 MSCHAPV2.Packet
}

func (p *MSCHAPV2Packet) String() string {
	return fmt.Sprintf("%s %s", p.PacketHeader.String(), p.MSCHAPV2.String())
}

func (p *MSCHAPV2Packet) Encode() []byte {
	return p.PacketHeader.encode([]byte(p.MSCHAPV2.Encode()))
}

// only put code identifier
type SimplePacket struct {
	PacketHeader
}

func (p *SimplePacket) String() string {
	return p.PacketHeader.String()
}

func (p *SimplePacket) Encode() (b []byte) {
	h := p.PacketHeader
	b = make([]byte, 4)
	b[0] = byte(h.Code)
	b[1] = byte(h.Identifier)
	binary.BigEndian.PutUint16(b[2:4], uint16(4))
	return b
}
