a golang radius library
=============================
This project originally forked from https://github.com/jessta/radius by bronze1man
And then forked from https://github.com/bronze1man/kmg/tree/master/third/kmgRadius

### document
* http://godoc.org/github.com/bronze1man/radius, which currently outdated
* http://en.wikipedia.org/wiki/RADIUS

### example
```go
package main

import (
	"github.com/bronze1man/kmg/third/radius"
	"github.com/bronze1man/kmg/kmgDebug"
	"github.com/bronze1man/kmg/kmgConsole"
)

func main() {
	// run the server in a new thread.
	// 在一个新线程里面一直运行服务器.
	radius.RunServer(":1812", []byte("sEcReT"), radius.Handler{
		Auth:       func(username string) (password string, exist bool) {
			if username!="a"{
				return "",false
			}
			return "b",true
		},
		AcctStart:  func(req radius.AcctRequest) {
			kmgDebug.Println("start",req)
		},
		AcctUpdate: func(req radius.AcctRequest) {
			kmgDebug.Println("update",req)
		},
		AcctStop:   func(req radius.AcctRequest) {
			kmgDebug.Println("stop",req)
		},
	})
	// wait for the system sign or ctrl-c to close the process.
	// 等待系统信号或者ctrl-c 关闭进程
	kmgConsole.WaitForExit()
}
```

### implemented
* a radius server can handle AccessRequest request from strongswan with ikev1-xauth-psk
* a radius server that can handle AccessRequest request from strongswan with ikev2-eap-psk with ms-chap-v2
* a radius server can handle AccountingRequest request from strongswan with ikev1-xauth-psk

### notice
* A radius client has not been implement.
* It works , but it is not stable.

### reference
* EAP MS-CHAPv2 packet format 								http://tools.ietf.org/id/draft-kamath-pppext-eap-mschapv2-01.txt
* EAP MS-CHAPv2 											https://tools.ietf.org/html/rfc2759
* RADIUS Access-Request part      							https://tools.ietf.org/html/rfc2865
* RADIUS Accounting-Request part  							https://tools.ietf.org/html/rfc2866
* RADIUS Support For Extensible Authentication Protocol 	https://tools.ietf.org/html/rfc3579
* RADIUS Implementation Issues and Suggested Fixes 			https://tools.ietf.org/html/rfc5080
* Extensible Authentication Protocol (EAP)                  https://tools.ietf.org/html/rfc3748

### TODO
* avpEapMessaget.Value error handle.
* implement radius client side.