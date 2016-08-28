package radius

import (
	"math/rand"

	"log"
	"github.com/Tunghsu/radius/MSCHAPV2"
	"github.com/Tunghsu/radius/eap"
)

const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandString(num int) string {
    b := make([]byte, num)
    for i, _ := range b {
        b[i] = chars[rand.Int() % len(chars)]
    }
    return string(b)
}

// 目前支持pap和mschapv2认证方式
func (p *server) radiusAccess(request *Packet) *Packet {
	log.Printf("Radius", "Access Request", request.ToStringMap())
	npac := request.Reply()

	username := request.GetUsername()
	password := request.GetPassword()
	if username == "" {
		//不支持的认证方式,或者包格式错误
		npac.AVPs = append(npac.AVPs, &StringAVP{Type: AVPTypeReplyMessage, Value: "need username"})
		npac.Code = CodeAccessReject
		log.Printf("[radius.radiusAccess] need username or auth method not support")
		return npac
	}
	AuthPassword, exist := p.handler.Auth(username)
	if !exist {
		log.Printf("[radius.radiusAccess] username [%s] not exist or do not have any transfer", username)
		npac.Code = CodeAccessReject
		return npac
	}
	//简单认证方式 pap
	if password != "" {
		if AuthPassword != password {
			log.Printf("[radius.radiusAccess] username [%s] password not match", username)
			npac.Code = CodeAccessReject
			return npac
		}
		npac.Code = CodeAccessAccept
		return npac
	}
	//复杂认证方式
	//如果没有输入密码,要求用户输入密码(遗留代码,应该是之前的bug导致的)
	e := request.GetEAPMessage()
	if e != nil {
		//第一次请求,eapCode应该是 Response
		// mschapv2 step 1
		switch e.Header().Type {
		case eap.TypeIdentity, eap.TypeLegacyNak:
			npac.Code = CodeAccessChallenge
			mschapV2Challenge := [16]byte{}
			_, err := rand.Read(mschapV2Challenge[:])
			if err != nil {
				panic(err)
			}
			sessionId := RandString(18)
			npac.SetState([]byte(sessionId))

			p.mschapMap[sessionId] = mschapStatus{
				Challenge: mschapV2Challenge,
			}
			npac.AddAVP(&EapAVP{
				Value: &eap.MSCHAPV2Packet{
					PacketHeader: eap.PacketHeader{
						Code:       eap.CodeRequest,
						Identifier: e.Header().Identifier,
						Type:       eap.TypeMSCHAPV2,
					},
					MSCHAPV2: &MSCHAPV2.ChallengePacket{
						Identifier: e.Header().Identifier,
						Challenge:  mschapV2Challenge,
						Name:       username,
					},
				},
			})
			return npac
		//TODO process next step read Response packet and write Success Request packet
		// reference http://tools.ietf.org/id/draft-kamath-pppext-eap-mschapv2-01.txt
		case eap.TypeMSCHAPV2:
			// mschapv2 step 3 and step 5
			if e.Header().Code != eap.CodeResponse {
				npac.Code = CodeAccessReject
				log.Printf("MSCHAPV2 step 3 fail! 1 eap.Code[%s]!=radius.EapCodeResponse", e.Header().Code)
				return npac
			}
			mschapv2I := e.(*eap.MSCHAPV2Packet).MSCHAPV2
			switch mschapv2I.OpCode() {
			case MSCHAPV2.OpCodeResponse:
				state := request.GetState()
				//step 3
				status, ok := p.mschapMap[string(state)]
				if !ok {
					npac.Code = CodeAccessReject
					log.Printf("MSCHAPV2 step 3 fail! 3 mschapStatus not found state:%s", state)
					return npac
				}
				status.NTResponse = mschapv2I.(*MSCHAPV2.ResponsePacket).NTResponse
				p.mschapMap[string(state)] = status
				successPacket := MSCHAPV2.ReplySuccessPacket(&MSCHAPV2.ReplySuccessPacketRequest{
					AuthenticatorChallenge: status.Challenge,
					Response:               mschapv2I.(*MSCHAPV2.ResponsePacket),
					Username:               []byte(username),
					Password:               []byte(AuthPassword),
					Message:                "success",
				})
				npac.AddAVP(&EapAVP{
					Value: &eap.MSCHAPV2Packet{
						PacketHeader: eap.PacketHeader{
							Code:       eap.CodeRequest,
							Identifier: e.Header().Identifier,
							Type:       eap.TypeMSCHAPV2,
						},
						MSCHAPV2: successPacket,
					},
				})
				npac.Code = CodeAccessChallenge
				return npac
			case MSCHAPV2.OpCodeSuccess:
				//step 5
				// reference http://www.ietf.org/rfc/rfc3079.txt
				state := request.GetState()
				//step 3
				status, ok := p.mschapMap[string(state)]
				if !ok {
					npac.Code = CodeAccessReject
					log.Printf("MSCHAPV2 step 5 fail! 5 mschapStatus not found state:%#v", state)
					return npac
				}

				npac.AddAVP(&EapAVP{
					Value: &eap.SimplePacket{
						PacketHeader: eap.PacketHeader{
							Code:       eap.CodeSuccess,
							Identifier: e.Header().Identifier,
						},
					},
				})
				npac.AddAVP(&StringAVP{
					Type:  AVPTypeUserName,
					Value: username,
				})
				//MS-MPPE-Encryption-Policy: Encryption-Allowed (1)
				npac.AddAVP(&BinaryAVP{
					Type:  AVPTypeVendorSpecific,
					Value: []byte{0x00, 0x00, 0x01, 0x37, 0x07, 0x06, 0, 0, 0, 1},
				})
				//MS-MPPE-Encryption-Types: RC4-40-128 (6)
				npac.AddAVP(&BinaryAVP{
					Type:  AVPTypeVendorSpecific,
					Value: []byte{0x00, 0x00, 0x01, 0x37, 0x08, 0x06, 0, 0, 0, 6},
				})
				sendkey, recvKey := MSCHAPV2.MsCHAPV2GetSendAndRecvKey([]byte(AuthPassword), status.NTResponse)
				npac.AddAVP(&VendorSpecificAVP{
					Value: NewMSMPPESendOrRecvKeyVSA(request, VendorTypeMSMPPESendKey, sendkey),
				})
				npac.AddAVP(&VendorSpecificAVP{
					Value: NewMSMPPESendOrRecvKeyVSA(request, VendorTypeMSMPPERecvKey, recvKey),
				})
				npac.Code = CodeAccessAccept
				npac.DeleteOneType(AVPTypeState)
				return npac
			default:
				npac.Code = CodeAccessReject
				log.Printf("MSCHAPV2 step 3 and 5 fail! 2.5 mschapv2I.OpCode()[%s]!= MSCHAPV2.OpCodeResponse",
					mschapv2I.OpCode())
				return npac
			}
		default:
			npac.Code = CodeAccessReject
			log.Printf("MSCHAPV2 eap fail! 4")
			return npac
		}
	}
	//不支持的认证方式,或者包格式错误
	npac.AVPs = append(npac.AVPs, &StringAVP{Type: AVPTypeReplyMessage, Value: "need password"})
	npac.Code = CodeAccessReject
	log.Printf("[radius.radiusAccess] username[%s] need password or auth method not support", username)
	return npac
}
