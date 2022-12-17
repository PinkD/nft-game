package main

import (
	"io"
	"net"
)

func JoinTCPConnection(c1, c2 net.Conn) {
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(c1, c2)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(c2, c1)
		errChan <- err
	}()
	<-errChan
	_ = c1.Close()
	_ = c2.Close()
	<-errChan
	close(errChan)
}
