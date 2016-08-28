package radius

import (
	"fmt"

	"log"
)

func (p *server) radiusAccountingRequest(request *Packet) *Packet {
	//对于strongswan服务器,如果golang处理时间太长,strongswan服务器会坏掉,目前的解决方案是全异步处理,以便快速返回结果.
	go p.asyncAccountingRequest(request)

	npac := request.Reply()
	npac.Code = CodeAccountingResponse
	return npac
}

func (p *server) asyncAccountingRequest(request *Packet) {
	acctReq := AcctRequest{
		SessionId:   request.GetAcctSessionId(),
		Username:    request.GetUsername(),
		SessionTime: request.GetAcctSessionTime(),
		InputBytes:  request.GetAcctTotalInputOctets(),
		OutputBytes: request.GetAcctTotalOutputOctets(),
		NasPort:     request.GetNASPort(),
	}
	switch request.GetAcctStatusType() {
	case AcctStatusTypeEnumStart:
		log.Printf("Radius", "Acct Start", request.ToStringMap())
		p.handler.AcctStart(acctReq)
	case AcctStatusTypeEnumInterimUpdate:
		p.handler.AcctUpdate(acctReq)
	case AcctStatusTypeEnumStop:
		log.Printf("Radius", "Acct Stop", request.ToStringMap())

		p.handler.AcctStop(acctReq)
	default:
		fmt.Errorf("radius.AccountingRequest AcctStatusType unknow %d", request.GetAcctStatusType())
	}
}
