package radius

import (
	"net"
	"log"
	"sync"
	"time"
)

type AcctRequest struct {
	SessionId   string //连接id
	Username    string
	SessionTime uint32 //连接时间
	InputBytes  uint64 //流入字节
	OutputBytes uint64 //流出字节
	NasPort     uint32
}

const (
	authServerPort	=	"1812"
	acctServerPort	=	"1813"
)

type Handler struct {
	// 有的协议需要明文密码来做各种hash的事情
	// exist返回false可以踢掉客户端
	// 同步调用
	Auth func(username string) (password string, exist bool)
	// 计费开始,来了一条新连接
	// 根据协议规定 此处返回给客户端的包,不能发送任何有效信息(比如踢掉客户端,请采用其他办法踢掉客户端)
	// 异步调用
	AcctStart func(acctReq AcctRequest)
	// 计费数据更新
	// 根据协议规定 此处返回给客户端的包,不能发送任何有效信息(比如踢掉客户端,请采用其他办法踢掉客户端)
	// 异步调用
	AcctUpdate func(acctReq AcctRequest)
	// 计费结束
	// 根据协议规定 此处返回给客户端的包,不能发送任何有效信息(比如踢掉客户端,请采用其他办法踢掉客户端)
	// 异步调用
	AcctStop func(acctReq AcctRequest)
}

//异步运行服务器,
// TODO 返回Closer以便可以关闭服务器,所有无法运行的错误panic出来,其他错误丢到kmgLog error里面.
// 如果不需要Closer可以直接忽略
func RunServer(address string, secret []byte, handler Handler) func() (error, error) {
	s := server{
		mschapMap: map[string]mschapStatus{},
		handler:   handler,
	}
	return RunServerWithPacketHandler(address, secret, s.PacketHandler)
}

type PacketHandler func(request *Packet) *Packet

//异步运行服务器,返回Closer以便可以关闭服务器,所有无法运行的错误panic出来,其他错误丢到kmgLog error里面.
func RunServerWithPacketHandler(address string, secret []byte, handler PacketHandler) func() (error, error) {
	exitWg := new(sync.WaitGroup)
	connChan := make(chan *net.UDPConn)
	stopServiceChan := make(chan struct{})

	go func() {
		authaddr, err := net.ResolveUDPAddr("udp", address+":"+authServerPort)
		if err != nil {
			panic(err)
		}
		authconn, err := net.ListenUDP("udp", authaddr)
		if err != nil {
			panic(err)
		}
		connChan <- authconn
		log.Println("Authentication server listening on", address+":"+authServerPort)
		exitWg.Add(1)

		acctaddr, err := net.ResolveUDPAddr("udp", address+":"+acctServerPort)
		if err != nil {
			panic(err)
		}
		acctconn, err := net.ListenUDP("udp", acctaddr)
		if err != nil {
			panic(err)
		}
		connChan <- acctconn
		log.Println("Accounting server listening on", address+":"+acctServerPort)
		exitWg.Add(1)

		go runSingleService(authconn, &stopServiceChan, secret, handler, exitWg)
		go runSingleService(acctconn, &stopServiceChan, secret, handler, exitWg)
		return
	}()
	conn1 := <-connChan
	conn2 := <-connChan
	close(connChan)
	return func() (error, error) {
		stopServiceChan <- struct{}{}
		stopServiceChan <- struct{}{}

		exitWg.Wait()
		close(stopServiceChan)
		return conn1.Close(), conn2.Close()
	}
}

func runSingleService(conn *net.UDPConn, stopServiceChan *chan struct{},
	secret []byte, handler PacketHandler, wg *sync.WaitGroup) {
	CONTROL:
	for {
		select {
		case <-(*stopServiceChan):
			break CONTROL
		default:
		}
		b := make([]byte, 4096)
		err := conn.SetReadDeadline(time.Now().Add(time.Second))
		if err != nil {
			panic(err)
		}
		n, senderAddress, err := conn.ReadFromUDP(b)
		if err != nil {
			networkError := err.(net.Error)
			if networkError.Timeout(){
				continue
			}
			panic(err)
		}
		go func(p []byte, senderAddress net.Addr) {
			pac, err := DecodeRequestPacket(secret, p)
			if err != nil {
				log.Printf("error", "radius.Decode", err.Error())
				return
			}

			npac := handler(pac)
			if npac == nil {
				// 特殊情况,返回nil,表示抛弃这个包.
				return
			}
			err = npac.Send(conn, senderAddress)
			if err != nil {
				log.Printf("error", "radius.Send", err.Error())
				return
			}
		}(b[:n], senderAddress)
	}
	wg.Done()
	return
}
