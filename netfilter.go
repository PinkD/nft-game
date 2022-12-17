package main

/*
#include "netfilter.h"

static void go_writeTCPData(EID id, void* buf, int len) {
    cchar_t* b = (cchar_t*)buf;
    printf("data in cgo: %02x%02x%02x%02x%02x%02x%02x%02x\n", b[0], b[1], b[2], b[3],
        b[4], b[5], b[6], b[7]);
    writeTCPData(id, (cchar_t*)buf, len);
    free(buf);
}

static void go_writeUDPData(EID id, cchar_t* ip, u_short port, void* buf, int len) {
    writeUDPData(id, ip, port, (cuc_t*)buf, len);
    free(buf);
}


#cgo CXXFLAGS: -Icgo/include
#cgo CFLAGS: -Icgo/include
#cgo LDFLAGS: -lws2_32 -Lcgo/lib -lnfapi
*/
import "C"
import (
	"context"
	"io"
	"log"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"unsafe"
)

var nfChan chan []byte

// handle icmp packet from netfilter, do not use it
//
//export _handleICMP
func _handleICMP(buf *C.cchar_t, len C.int) {
	packet := toBytes(buf, len)

	// TODO: change packet src addr
	_ = packet
}

// send packet to netfilter, do not use it
func _send(packet []byte) {
	_ = packet
	// TODO: remove
	//_ = C.ipPostReceive(buf, l)
}

var globalNetFilter *NetFilter

var udpConnMap SyncMap[C.EID, net.PacketConn]
var tcpConnMap SyncMap[C.EID, net.Conn]
var tcpAddrMap SyncMap[C.EID, *netip.AddrPort]
var portEIDMap SyncMap[C.u_short, C.EID]

func parseAddrPort(ip *C.cchar_t, port C.u_short) netip.AddrPort {
	var addr [4]byte
	copy(addr[:], toBytes(ip, 4))
	return netip.AddrPortFrom(netip.AddrFrom4(addr), uint16(port))
}

var udpAddrMap SyncMap[C.EID, *SyncMap[string, int]]

// handle udp packet from netfilter, do not use it
//
//export _handleUDP
func _handleUDP(eid C.EID, ip *C.cchar_t, port C.u_short, buf *C.cchar_t, size C.int) {
	log.Println("_handleUDP", eid)
	conn, ok := udpConnMap.Load(eid)
	addr := net.UDPAddrFromAddrPort(parseAddrPort(ip, port))
	if !ok {
		log.Printf("Dial udp for %s, eid %v", addr.String(), eid)
		ip, _ := netip.ParseAddr(globalNetFilter.conf.LocalIPs[0])
		localAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0))
		c, err := globalNetFilter.dev.ListenUDP(localAddr)
		if err != nil {
			log.Printf("Failed to dial udp for %v", eid)
		}
		conn = c
		udpConnMap.Store(eid, c)
		go func() {
			buffer := make([]byte, bufferSize)
			for {
				n, remoteAddr, err := c.ReadFrom(buffer)
				if err != nil {
					if err == io.EOF {
						// connection closed
						return
					}
					log.Printf("Failed to read data from %v: %s", eid, err)
				}
				log.Printf("udp data from %s, len is %d", remoteAddr.String(), n)
				//log.Printf("udp data %02x%02x%02x%02x%02x%02x%02x%02x",
				//	buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7])
				addr := remoteAddr.(*net.UDPAddr)
				ip := C.CString(addr.IP.String())
				port := C.u_short(addr.Port)
				C.go_writeUDPData(eid, ip, port, C.CBytes(buffer[:n]), C.int(n))
				C.free(unsafe.Pointer(ip))
			}
		}()
	}
	m, ok := udpAddrMap.Load(eid)
	if !ok {
		m = &SyncMap[string, int]{}
		udpAddrMap.Store(eid, m)
	}
	if v, ok := m.Load(addr.String()); ok {
		v++
		m.Store(addr.String(), v)
	} else {
		m.Store(addr.String(), 1)
	}
	log.Printf("%v send data to %s, len is %v", eid, addr.String(), size)
	packet := toBytes(buf, size)
	_, err := conn.WriteTo(packet, addr)
	if err != nil {
		log.Printf("Failed to send data to %s, err : %s", addr.String(), err)
	}
	//m.Range(func(k string, v int) bool {
	//	log.Printf("%v->%s: %d", eid, k, v)
	//	return true
	//})
}

// handle close udp connection from netfilter, do not use it
//
//export _handleCloseUDP
func _handleCloseUDP(eid C.EID) {
	c, ok := udpConnMap.LoadAndDelete(eid)
	if !ok {
		log.Println("UDP connection not found for eid", eid)
		return
	}
	_ = c.Close()
}

// handle udp packet from netfilter, do not use it
//
//export _handleDialTCP
func _handleDialTCP(eid C.EID, localPort C.u_short, ip *C.cchar_t, port C.u_short) {
	_, ok := tcpAddrMap.Load(eid)
	if ok {
		log.Println("Duplicated eid", eid)
		return
	}
	addr := parseAddrPort(ip, port)
	log.Printf("handle tcp to %s", addr.String())
	portEIDMap.Store(localPort, eid)
	tcpAddrMap.Store(eid, &addr)
}

// handle tcp data from netfilter, do not use it
//
//export _handleTCP
func _handleTCP(eid C.EID, buf *C.cchar_t, len C.int) {
	conn, ok := tcpConnMap.Load(eid)
	if !ok {
		log.Println("No tcp connection for eid", eid)
		return
	}
	packet := toBytes(buf, len)

	_, err := conn.Write(packet)
	if err != nil {
		log.Println("Failed to send data through", eid, err)
	}
}

// handle close tcp connection from netfilter, do not use it
//
//export _handleCloseTCP
func _handleCloseTCP(eid C.EID, localPort C.u_short) {
	portEIDMap.Delete(localPort)
	c, ok := tcpConnMap.LoadAndDelete(eid)
	if !ok {
		return
	}
	_ = c.Close()
}

func toBytes(buf *C.cchar_t, len C.int) []byte {
	return C.GoBytes(unsafe.Pointer(buf), len)
}

type NetFilter struct {
	ctx        context.Context
	cancel     context.CancelFunc
	driverName string
	conf       *Conf
	dev        *Device

	pool    *sync.Pool
	inChan  chan []byte
	outChan chan []byte
}

func NewNetFilter(driverName string, conf *Conf) *NetFilter {
	if globalNetFilter != nil {
		panic("only allow one netfilter instance for now")
	}
	pool := &sync.Pool{
		New: func() any {
			return make([]byte, bufferSize)
		},
	}
	nf := &NetFilter{
		ctx:        context.Background(),
		driverName: driverName,
		conf:       conf,
		pool:       pool,
		inChan:     make(chan []byte),
		outChan:    make(chan []byte),
	}
	globalNetFilter = nf
	return nf
}

func (nf *NetFilter) setupTCPProxyConnection() (uint16, error) {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP: net.IPv4(127, 0, 0, 1),
	})
	if err != nil {
		return 0, err
	}
	addr := l.Addr().(*net.TCPAddr)
	log.Printf("listen on %s", addr.String())
	go func() {
		for {
			c, err := l.AcceptTCP()
			if err != nil {
				log.Printf("Failed to accept for %s", addr.String())
			}
			remoteAddr := c.RemoteAddr().(*net.TCPAddr)
			log.Printf("Connection from %s", remoteAddr.String())

			eid, ok := portEIDMap.LoadAndDelete(C.u_short(uint16(remoteAddr.Port)))
			if !ok {
				log.Printf("No nf connection found for %s", remoteAddr.String())
				continue
			}
			addr, ok := tcpAddrMap.LoadAndDelete(eid)
			if !ok {
				log.Printf("No tcp connection found for %s", remoteAddr.String())
				continue
			}
			log.Printf("Dial %s for eid %v ", addr, eid)
			conn, err := globalNetFilter.dev.DialTCPAddrPort(*addr)
			if err != nil {
				log.Println("Failed to dial tcp", addr.String(), err)
				return
			}
			tcpConnMap.Store(eid, conn)
			log.Printf("Connection to %s for eid %v enstablished", addr, eid)
			go JoinTCPConnection(c, conn)
		}
	}()
	return uint16(addr.Port), nil
}

func (nf *NetFilter) Start() error {
	port, err := nf.setupTCPProxyConnection()
	if err != nil {
		return err
	}
	nf.setupNetfilter(port)
	tunDev, err := NewTun(nf.conf.WgConf)
	if err != nil {
		return err
	}
	nf.dev = tunDev
	nf.handleFilterRule()
	nf.handlePacketFromNF()
	//nf.handlePacketFromWG()
	nf.ctx, nf.cancel = context.WithCancel(nf.ctx)
	return nil
}

func (nf *NetFilter) Stop() {
	close(nf.inChan)
	close(nf.outChan)
	nf.cancel()
	_ = nf.dev.Close()
	nf.destroyNetfilter()
}

func (nf *NetFilter) setupNetfilter(port uint16) {
	cs := C.CString(nf.driverName)
	ret := C.initDriver(cs, C.u_short(port))
	C.free(unsafe.Pointer(cs))
	if ret != 0 {
		panic("failed to init driver")
	}
}

func (nf *NetFilter) destroyNetfilter() {
	C.freeDriver()
}

func (nf *NetFilter) handleFilterRule() {
	for _, name := range nf.conf.processNames {
		name = strings.ToLower(name)
		cs := C.CString(name)
		C.addFilterForProcess(cs)
		C.free(unsafe.Pointer(cs))
	}
}

func (nf *NetFilter) handlePacketFromNF() {
	go func() {
		cpuNum := runtime.NumCPU()/2 + 1
		for i := 0; i < cpuNum; i++ {
			go func() {
				for packet := range nfChan {
					_ = packet
					println("packet from nf")
					//_, err := nf.dev.Write(packet, len(packet))
					//if err != nil {
					//	log.Println(err)
					//}
				}
			}()
		}
	}()
}

// default buffer size is max mtu
const bufferSize = 1500

func (nf *NetFilter) handlePacketFromWG() {
	wgChan := make(chan []byte)
	go func() {
		for !exit {
			buff := nf.pool.Get().([]byte)
			_, err := nf.dev.Read(buff, 0)
			if err != nil {
				log.Println(err)
			}
			select {
			case wgChan <- buff:
			default:
				log.Println("packet from wg dropped")
			}
		}
	}()
	cpuNum := runtime.NumCPU()/2 + 1
	for i := 0; i < cpuNum; i++ {
		go func() {
			for packet := range wgChan {
				// TODO: change dst addr
				_send(packet)
				nf.pool.Put(packet)
			}
		}()
	}
}

func init() {
	nfChan = make(chan []byte)
}
