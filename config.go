package main

import (
	"errors"
	"net"
	"strings"

	"gopkg.in/ini.v1"
)

type WgConf struct {
	LocalIPs      []string
	DNSs          []string
	PeerKey       string
	PrivateKey    string
	Endpoint      string
	MTU           int
	KeepAliveTime int
}

type Conf struct {
	*WgConf
	processNames []string
}

const (
	defaultMTU = 1420
)

func ParseWgConf(file string) (*WgConf, error) {
	f, err := ini.Load(file)
	if err != nil {
		return nil, err
	}
	peerSection, err := f.GetSection("Peer")
	if err != nil {
		return nil, err
	}
	peerKey := peerSection.Key("PublicKey").Value()
	if len(peerKey) == 0 {
		return nil, errors.New("no peer key")
	}
	endpoint := peerSection.Key("Endpoint").Value()
	if len(endpoint) == 0 {
		return nil, errors.New("no endpoint")
	}
	keepaliveTime, _ := peerSection.Key("PersistentKeepalive").Int()
	interfaceSection, err := f.GetSection("Interface")
	if err != nil {
		return nil, err
	}
	privateKey := interfaceSection.Key("PrivateKey").Value()
	if len(privateKey) == 0 {
		return nil, errors.New("no private key")
	}
	mtu, _ := interfaceSection.Key("MTU").Int()
	if mtu == 0 {
		mtu = defaultMTU
	}
	if mtu < 1024 || mtu > 65535 {
		return nil, errors.New("mtu should be between 1024-65535")
	}
	conf := &WgConf{
		MTU:           mtu,
		PrivateKey:    privateKey,
		DNSs:          []string{"8.8.8.8"},
		PeerKey:       peerKey,
		Endpoint:      endpoint,
		KeepAliveTime: keepaliveTime,
	}
	addr := interfaceSection.Key("Address").Value()
	if len(addr) == 0 {
		return nil, errors.New("no address")
	}
	addresses := strings.Split(addr, ",")
	for _, a := range addresses {
		addr, _, err := net.ParseCIDR(a)
		if err != nil {
			return nil, err
		}
		conf.LocalIPs = append(conf.LocalIPs, addr.String())
	}
	conf.PrivateKey = privateKey
	return conf, nil
}
