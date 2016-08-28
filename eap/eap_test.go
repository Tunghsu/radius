package eap

import (
	//"fmt"
	"testing"

	. "github.com/bronze1man/kmg/kmgTest"
	"github.com/bronze1man/kmg/third/radius/MSCHAPV2"
)

func TestEapMsChapV2ChallengeDecode(ot *testing.T) {
	inByte := []byte{0x01, 0xED, 0x00, 0x24, 0x1A, 0x01, 0xED, 0x00, 0x1F, 0x10, 0x24, 0xDC, 0x3D, 0x6D, 0xB5, 0x66, 0xED, 0x25, 0xE4,
		0x90, 0x49, 0x2C, 0x6E, 0xA2, 0x65, 0xCD, 0x73, 0x74, 0x72, 0x6F, 0x6E, 0x67, 0x53, 0x77, 0x61, 0x6E}
	eapI, err := Decode(inByte)
	Equal(err, nil)
	Equal(eapI.Header().Code, CodeRequest)
	Equal(eapI.Header().Identifier, uint8(0xED))
	Equal(eapI.Header().Type, TypeMSCHAPV2)
	outByte := eapI.Encode()
	Equal(inByte, outByte)
	eap, ok := eapI.(*MSCHAPV2Packet)
	Equal(ok, true)
	Equal(eap.MSCHAPV2.OpCode(), MSCHAPV2.OpCodeChallenge)
}

func TestFromStrongswan1(ot *testing.T) {
	//step4
	inByte4 := []byte{0x02, 0x23, 0x00, 0x06, 0x1A, 0x03}
	eap4I, err := Decode(inByte4)
	Equal(err, nil)
	Equal(eap4I.Header().Code, CodeResponse)
	Equal(eap4I.Header().Identifier, uint8(0x23))
	Equal(eap4I.Header().Type, TypeMSCHAPV2)
	mschap4I := eap4I.(*MSCHAPV2Packet).MSCHAPV2
	Equal(mschap4I.OpCode(), MSCHAPV2.OpCodeSuccess)
	_, ok := mschap4I.(*MSCHAPV2.SimplePacket)
	Equal(ok, true)
	Equal(eap4I.Encode(), inByte4)

	//step5
	inByte5 := []byte{0x03, 0x23, 0x00, 0x04}
	eap5I, err := Decode(inByte5)
	Equal(err, nil)
	Equal(eap5I.Header().Code, CodeSuccess)
	Equal(eap5I.Header().Identifier, uint8(0x23))
	Equal(eap5I.Encode(), inByte5)
}
