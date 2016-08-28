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
	closeServer := radius.RunServer("0.0.0.0:1812", []byte("testing123"), radius.Handler{
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
	err := closeServer()
	if err != nil {
		log.Println("Server close failed: ", err)
	}
	log.Println("stopping server...")
}