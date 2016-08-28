package radius

import (
	"strconv"
)

type Code uint8

const (
	CodeAccessRequest      Code = 1
	CodeAccessAccept       Code = 2
	CodeAccessReject       Code = 3
	CodeAccountingRequest  Code = 4
	CodeAccountingResponse Code = 5
	CodeAccessChallenge    Code = 11
	CodeStatusServer       Code = 12 //(experimental)
	CodeStatusClient       Code = 13 //(experimental)
	CodeReserved           Code = 255
)

func (p Code) String() string {
	switch p {
	case CodeAccessRequest:
		return "AccessRequest"
	case CodeAccessAccept:
		return "AccessAccept"
	case CodeAccessReject:
		return "AccessReject"
	case CodeAccountingRequest:
		return "AccountingRequest"
	case CodeAccountingResponse:
		return "AccountingResponse"
	case CodeAccessChallenge:
		return "AccessChallenge"
	case CodeStatusServer:
		return "StatusServer"
	case CodeStatusClient:
		return "StatusClient"
	case CodeReserved:
		return "Reserved"
	}
	return "unknown code " + strconv.Itoa(int(p))
}
