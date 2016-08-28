package main

import (
    	"github.com/Tunghsu/radius"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
    // run the server in a new thread.
    // 在一个新线程里面一直运行服务器.
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	closeServers := radius.RunServer("0.0.0.0", []byte("testing123"), radius.Handler{
		Auth:       func(username string) (password string, exist bool) {
		    if username!="a"{
			return "",false
		    }
		    return "b",true
		},
		AcctStart:  func(req radius.AcctRequest) {
		    log.Println("start",req)
		},
		AcctUpdate: func(req radius.AcctRequest) {
		    log.Println("update",req)
		},
		AcctStop:   func(req radius.AcctRequest) {
		    log.Println("stop",req)
		},
   	 })
    // wait for the system sign or ctrl-c to close the process.
    // 等待系统信号或者ctrl-c 关闭进程
	<-signalChan

	log.Println("stopping server...")
	err1, err2 := closeServers()
	if err1 != nil {
		log.Println("Server close failed: ", err1)
	}
	if err2 != nil {
		log.Println("Server close failed: ", err2)
	}
	log.Println("server stopped...")
}