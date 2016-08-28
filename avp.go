package radius

import (
	"bytes"
	"crypto"
	_ "crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"strconv"

	"github.com/Tunghsu/radius/eap"
)

type AVP interface {
	GetType() AVPType
	Encode() (b []byte, err error)
	Copy() AVP

	String() string
	GetValue() interface{}
	ValueAsString() string
}

func avpDecode(p *Packet, b []byte) (avp AVP, err error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("[avp.Decode] protocol error 1 buffer too small")
	}
	typ := AVPType(b[0])
	data := b[2:]
	decoder := getTypeDesc(typ).decoder
	return decoder(p, typ, data)
}

func encodeWithByteSlice(typ AVPType, data []byte) (b []byte, err error) {
	if len(data) > 253 {
		return nil, fmt.Errorf("[encodeWithByteSlice] data length %d overflow(should less than 253)", len(data))
	}
	length := len(data) + 2
	b = make([]byte, length)
	b[0] = byte(typ)
	b[1] = byte(length)
	copy(b[2:], data)
	return b, nil
}
func avpBinary(p *Packet, typ AVPType, data []byte) (avp AVP, err error) {
	return &BinaryAVP{
		Type:  typ,
		Value: data,
	}, nil
}

type BinaryAVP struct {
	Type  AVPType
	Value []byte
}

func (a *BinaryAVP) GetType() AVPType {
	return a.Type
}
func (a *BinaryAVP) String() string {
	return fmt.Sprintf("Type: %s Value: %#v", a.Type, a.Value)
}
func (a *BinaryAVP) Encode() (b []byte, err error) {
	if len(a.Value) > 253 {
		return nil, fmt.Errorf("[BinaryAVP.Encode] len(a.Value)[%d]>253", len(a.Value))
	}
	return encodeWithByteSlice(a.Type, a.Value)
}
func (a *BinaryAVP) Copy() AVP {
	return &BinaryAVP{
		Type:  a.Type,
		Value: append([]byte(nil), a.Value...),
	}
}
func (a *BinaryAVP) GetValue() interface{} {
	return a.Value
}
func (a *BinaryAVP) ValueAsString() string {
	return hex.EncodeToString(a.Value)
}

func avpString(p *Packet, typ AVPType, data []byte) (avp AVP, err error) {
	return &StringAVP{
		Type:  typ,
		Value: string(data),
	}, nil
}

type StringAVP struct {
	Type  AVPType
	Value string
}

func (a *StringAVP) GetType() AVPType {
	return a.Type
}
func (a *StringAVP) String() string {
	return fmt.Sprintf("Type: %s Value: %s", a.Type, a.Value)
}
func (a *StringAVP) Encode() (b []byte, err error) {
	if len(a.Value) > 253 {
		return nil, fmt.Errorf("[StringAVP.Encode] len(a.Value)[%d]>253", len(a.Value))
	}
	return encodeWithByteSlice(a.Type, []byte(a.Value))
}
func (a *StringAVP) Copy() AVP {
	return &StringAVP{
		Type:  a.Type,
		Value: a.Value,
	}
}
func (a *StringAVP) GetValue() interface{} {
	return a.Value
}

func (a *StringAVP) ValueAsString() string {
	return a.Value
}

func avpIP(p *Packet, typ AVPType, data []byte) (avp AVP, err error) {
	return &IpAVP{
		Type:  typ,
		Value: net.IP(data),
	}, nil
}

type IpAVP struct {
	Type  AVPType
	Value net.IP
}

func (a *IpAVP) GetType() AVPType {
	return a.Type
}
func (a *IpAVP) String() string {
	return fmt.Sprintf("Type: %s Value: %s", a.Type, a.Value)
}
func (a *IpAVP) Encode() (b []byte, err error) {
	return encodeWithByteSlice(a.Type, []byte(a.Value))
}
func (a *IpAVP) Copy() AVP {
	return &IpAVP{
		Type:  a.Type,
		Value: net.IP(append([]byte(nil), []byte(a.Value)...)),
	}
}
func (a *IpAVP) GetValue() interface{} {
	return a.Value
}
func (a *IpAVP) ValueAsString() string {
	return a.Value.String()
}

func avpUint32(p *Packet, typ AVPType, data []byte) (avp AVP, err error) {
	if len(data) != 4 {
		return nil, fmt.Errorf("[avpUint32] len(data)[%d]!=4", len(data))
	}
	return &Uint32AVP{
		Type:  typ,
		Value: uint32(binary.BigEndian.Uint32(data)),
	}, nil
}

type Uint32AVP struct {
	Type  AVPType
	Value uint32
}

func (a *Uint32AVP) GetType() AVPType {
	return a.Type
}
func (a *Uint32AVP) String() string {
	return fmt.Sprintf("Type: %s Value: %d", a.Type, a.Value)
}
func (a *Uint32AVP) Encode() (b []byte, err error) {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, a.Value)
	return encodeWithByteSlice(a.Type, data)
}
func (a *Uint32AVP) Copy() AVP {
	return &Uint32AVP{
		Type:  a.Type,
		Value: a.Value,
	}
}
func (a *Uint32AVP) GetValue() interface{} {
	return a.Value
}
func (a *Uint32AVP) ValueAsString() string {
	return strconv.Itoa(int(a.Value))
}

func avpPassword(p *Packet, typ AVPType, data []byte) (avp AVP, err error) {
	fmt.Printf("%#v\n", data)
	if len(data) < 16 {
		return nil, fmt.Errorf("[avpPassword] len(data)[%d]<16", len(data))
	}
	if len(data) > 128 {
		return nil, fmt.Errorf("[avpPassword] len(data)[%d]>128", len(data))
	}
	//Decode password. XOR against md5(p.server.secret+Authenticator)
	m := crypto.Hash(crypto.MD5).New()
	m.Write(p.Secret)
	m.Write(p.Authenticator[:])
	md := m.Sum(nil)
	pass := append([]byte(nil), data...)
	blockNum := len(pass) / 16
	if len(pass)%16 != 0 {
		return nil, fmt.Errorf("[avpPassword] blockNum[%d]%%16!=0", blockNum)
	}
	outputPass := make([]byte, len(pass))
	for i := 0; i < blockNum; i++ {
		for j := 0; j < 16; j++ {
			outputPass[i*16+j] = pass[i*16+j] ^ md[j]
		}
		m := crypto.Hash(crypto.MD5).New()
		m.Write(p.Secret)
		m.Write(pass[i*16 : i*16+16])
		md = m.Sum(nil)
	}
	outputPass = bytes.TrimRight(outputPass, string([]rune{0}))
	avpP := &PasswordAVP{
		Value: string(outputPass),
	}
	avpP.SetPacket(p)
	return avpP, nil
}

type PasswordAVP struct {
	packet *Packet
	Value  string // plain of password
}

func (a *PasswordAVP) GetType() AVPType {
	return AVPTypeUserPassword
}
func (a *PasswordAVP) String() string {
	return fmt.Sprintf("Type: %s Value: %s", a.GetType(), a.Value)
}
func (a *PasswordAVP) SetPacket(p *Packet) {
	a.packet = p
}
func (a *PasswordAVP) Copy() AVP {
	return &PasswordAVP{
		packet: a.packet,
		Value:  a.Value,
	}
}
func (a *PasswordAVP) GetValue() interface{} {
	return a.Value
}

func (a *PasswordAVP) ValueAsString() string {
	return a.Value
}

//you need set packet before encode
func (a *PasswordAVP) Encode() (b []byte, err error) {
	m := crypto.Hash(crypto.MD5).New()
	m.Write(a.packet.Secret)
	m.Write(a.packet.Authenticator[:])
	md := m.Sum(nil)
	if len(a.Value) > 128 {
		return nil, fmt.Errorf("[PasswordAVP.Encode] len(data)[%d]>128", len(a.Value))
	}
	inPassLen := len(a.Value) / 16 * 16
	if len(a.Value)%16 != 0 {
		inPassLen += 16
	}
	pass := make([]byte, inPassLen)
	outPass := make([]byte, inPassLen)
	copy(pass, a.Value)
	blockNum := inPassLen / 16
	for i := 0; i < blockNum; i++ {
		for j := 0; j < 16; j++ {
			outPass[i*16+j] = pass[i*16+j] ^ md[j]
		}
		m := crypto.Hash(crypto.MD5).New()
		m.Write(a.packet.Secret)
		m.Write(outPass[i*16 : i*16+16])
		md = m.Sum(nil)
	}
	return encodeWithByteSlice(AVPTypeUserPassword, outPass)
}

// t should from a uint32 type like AcctStatusTypeEnum
func avpUint32Enum(t Stringer) func(p *Packet, typ AVPType, data []byte) (avp AVP, err error) {
	return func(p *Packet, typ AVPType, data []byte) (avp AVP, err error) {
		value := reflect.New(reflect.TypeOf(t)).Elem()
		value.SetUint(uint64(binary.BigEndian.Uint32(data)))
		valueI := value.Interface().(Stringer)
		return &Uint32EnumAVP{
			Type:  typ,
			Value: valueI,
		}, nil
	}
}

type Uint32EnumAVP struct {
	Type  AVPType
	Value Stringer // value should derive from a uint32 type like AcctStatusTypeEnum
}

func (a *Uint32EnumAVP) GetType() AVPType {
	return a.Type
}
func (a *Uint32EnumAVP) String() string {
	return fmt.Sprintf("Type: %s Value: %s", a.GetType(), a.Value)
}
func (a *Uint32EnumAVP) Encode() (b []byte, err error) {
	b = make([]byte, 4)
	value := reflect.ValueOf(a.Value)
	out := value.Uint()
	if out >= (1 << 32) {
		panic("[Uint32EnumAVP.Encode] enum number overflow")
	}
	binary.BigEndian.PutUint32(b, uint32(out))
	return encodeWithByteSlice(a.Type, b)
}
func (a *Uint32EnumAVP) Copy() AVP {
	return &Uint32EnumAVP{
		Type:  a.Type,
		Value: a.Value,
	}
}
func (a *Uint32EnumAVP) GetValue() interface{} {
	return a.Value
}
func (a *Uint32EnumAVP) ValueAsString() string {
	return a.Value.String()
}

func avpEapMessage(p *Packet, typ AVPType, data []byte) (avp AVP, err error) {
	eap, err := eap.Decode(data)
	if err != nil {
		return nil, err
	}
	return &EapAVP{
		Value: eap,
	}, nil
}

type EapAVP struct {
	Value eap.Packet
}

func (a *EapAVP) GetType() AVPType {
	return AVPTypeEAPMessage
}
func (a *EapAVP) String() string {
	return fmt.Sprintf("Type: %s Value: %s", a.GetType(), a.Value.String())
}
func (a *EapAVP) Encode() (b []byte, err error) {
	b = a.Value.Encode()
	return encodeWithByteSlice(AVPTypeEAPMessage, b)
}

//TODO real copy
func (a *EapAVP) Copy() AVP {
	return &EapAVP{
		Value: a.Value,
	}
}
func (a *EapAVP) GetValue() interface{} {
	return a.Value
}
func (a *EapAVP) ValueAsString() string {
	return a.Value.String()
}

func avpVendorSpecific(p *Packet, typ AVPType, data []byte) (avp AVP, err error) {
	vsa, err := vsaDecode(p, data)
	if err != nil {
		return nil, err
	}
	return &VendorSpecificAVP{
		Value: vsa,
	}, nil
}

type VendorSpecificAVP struct {
	Value VSA
}

func (a *VendorSpecificAVP) GetType() AVPType {
	return AVPTypeVendorSpecific
}
func (a *VendorSpecificAVP) String() string {
	return fmt.Sprintf("Type: %s Value: %s", a.GetType(), a.Value.String())
}
func (a *VendorSpecificAVP) Encode() (b []byte, err error) {
	b, err = a.Value.Encode()
	if err != nil {
		return nil, err
	}
	return encodeWithByteSlice(AVPTypeVendorSpecific, b)
}

//TODO real copy
func (a *VendorSpecificAVP) Copy() AVP {
	return &VendorSpecificAVP{
		Value: a.Value,
	}
}
func (a *VendorSpecificAVP) GetValue() interface{} {
	return a.Value
}
func (a *VendorSpecificAVP) ValueAsString() string {
	return a.Value.String()
}

type Stringer interface {
	String() string
}

type AcctStatusTypeEnum uint32

const (
	AcctStatusTypeEnumStart         AcctStatusTypeEnum = 1
	AcctStatusTypeEnumStop          AcctStatusTypeEnum = 2
	AcctStatusTypeEnumInterimUpdate AcctStatusTypeEnum = 3
	AcctStatusTypeEnumAccountingOn  AcctStatusTypeEnum = 7
	AcctStatusTypeEnumAccountingOff AcctStatusTypeEnum = 8
)

func (e AcctStatusTypeEnum) String() string {
	switch e {
	case AcctStatusTypeEnumStart:
		return "Start"
	case AcctStatusTypeEnumStop:
		return "Stop"
	case AcctStatusTypeEnumInterimUpdate:
		return "InterimUpdate"
	case AcctStatusTypeEnumAccountingOn:
		return "AccountingOn"
	case AcctStatusTypeEnumAccountingOff:
		return "AccountingOff"
	}
	return "unknow code " + strconv.Itoa(int(e))
}

type NASPortTypeEnum uint32

// TODO finish it
const (
	NASPortTypeEnumAsync            NASPortTypeEnum = 0
	NASPortTypeEnumSync             NASPortTypeEnum = 1
	NASPortTypeEnumISDNSync         NASPortTypeEnum = 2
	NASPortTypeEnumISDNSyncV120     NASPortTypeEnum = 3
	NASPortTypeEnumISDNSyncV110     NASPortTypeEnum = 4
	NASPortTypeEnumVirtual          NASPortTypeEnum = 5
	NASPortTypeEnumPIAFS            NASPortTypeEnum = 6
	NASPortTypeEnumHDLCClearChannel NASPortTypeEnum = 7
	NASPortTypeEnumEthernet         NASPortTypeEnum = 15
	NASPortTypeEnumCable            NASPortTypeEnum = 17
)

func (e NASPortTypeEnum) String() string {
	switch e {
	case NASPortTypeEnumAsync:
		return "Async"
	case NASPortTypeEnumSync:
		return "Sync"
	case NASPortTypeEnumISDNSync:
		return "ISDNSync"
	case NASPortTypeEnumISDNSyncV120:
		return "ISDNSyncV120"
	case NASPortTypeEnumISDNSyncV110:
		return "ISDNSyncV110"
	case NASPortTypeEnumVirtual:
		return "Virtual"
	case NASPortTypeEnumPIAFS:
		return "PIAFS"
	case NASPortTypeEnumHDLCClearChannel:
		return "HDLCClearChannel"
	case NASPortTypeEnumEthernet:
		return "Ethernet"
	case NASPortTypeEnumCable:
		return "Cable"
	}
	return "unknow code " + strconv.Itoa(int(e))
}

type ServiceTypeEnum uint32

// TODO finish it
const (
	ServiceTypeEnumLogin          ServiceTypeEnum = 1
	ServiceTypeEnumFramed         ServiceTypeEnum = 2
	ServiceTypeEnumCallbackLogin  ServiceTypeEnum = 3
	ServiceTypeEnumCallbackFramed ServiceTypeEnum = 4
	ServiceTypeEnumOutbound       ServiceTypeEnum = 5
)

func (e ServiceTypeEnum) String() string {
	switch e {
	case ServiceTypeEnumLogin:
		return "Login"
	case ServiceTypeEnumFramed:
		return "Framed"
	case ServiceTypeEnumCallbackLogin:
		return "CallbackLogin"
	case ServiceTypeEnumCallbackFramed:
		return "CallbackFramed"
	case ServiceTypeEnumOutbound:
		return "Outbound"
	}
	return "unknow code " + strconv.Itoa(int(e))
}

type AcctTerminateCauseEnum uint32

// TODO finish it
const (
	AcctTerminateCauseEnumUserRequest AcctTerminateCauseEnum = 1
	AcctTerminateCauseEnumLostCarrier AcctTerminateCauseEnum = 2
	AcctTerminateCauseEnumLostService AcctTerminateCauseEnum = 3
	AcctTerminateCauseEnumIdleTimeout AcctTerminateCauseEnum = 4
)

func (e AcctTerminateCauseEnum) String() string {
	switch e {
	case AcctTerminateCauseEnumUserRequest:
		return "UserRequest"
	case AcctTerminateCauseEnumLostCarrier:
		return "LostCarrier"
	case AcctTerminateCauseEnumLostService:
		return "LostService"
	case AcctTerminateCauseEnumIdleTimeout:
		return "IdleTimeout"
	}
	return "unknow code " + strconv.Itoa(int(e))
}
