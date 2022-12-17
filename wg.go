package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func base64ToHex(s string) string {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(data)
}

type Device struct {
	tun.Device
	dev *device.Device
	*netstack.Net
}

func (d *Device) Close() error {
	d.dev.Close()
	return d.Device.Close()
}

func NewTun(conf *WgConf) (*Device, error) {
	var localIPs []netip.Addr
	var dnsIPs []netip.Addr
	for _, ip := range conf.LocalIPs {
		localIPs = append(localIPs, netip.MustParseAddr(ip))
	}
	for _, ip := range conf.DNSs {
		dnsIPs = append(dnsIPs, netip.MustParseAddr(ip))
	}
	tunDev, n, err := netstack.CreateNetTUN(
		localIPs,
		dnsIPs,
		conf.MTU)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	err = dev.IpcSet(fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
allowed_ip=%s

`,
		base64ToHex(conf.PrivateKey), base64ToHex(conf.PeerKey), conf.Endpoint, "0.0.0.0/0"))
	if err != nil {
		return nil, err
	}
	err = dev.Up()
	if err != nil {
		return nil, err
	}
	return &Device{tunDev, dev, n}, nil
}
