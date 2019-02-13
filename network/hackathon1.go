package network

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

type HackathonNetworkRot struct{}

func (h *HackathonNetworkRot) privateNetworkIP() (ip string, err error) {
	iFaces, err := net.Interfaces()

	if err != nil {
		return ip, err
	}
	for _, iFace := range iFaces {

		if iFace.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iFace.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}

		addrs, err := iFace.Addrs()
		if err != nil {
			return ip, err
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}

	return "", errors.New("are you connected to the network?")
}

func (h *HackathonNetworkRot) getMacAddr() (addr string) {
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, i := range interfaces {
			if i.Flags&net.FlagUp != 0 && bytes.Compare(i.HardwareAddr, nil) != 0 {
				// Don't use random as we have a real address
				addr = i.HardwareAddr.String()
				break
			}
		}
	}
	return addr
}

func (h *HackathonNetworkRot) SendPacket(destination string, packet []byte, handle *pcap.Handle) (err error) {

	srcMac, _ := net.ParseMAC(h.getMacAddr())
	eth := &layers.Ethernet{}
	eth.DstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	eth.SrcMAC = srcMac
	eth.EthernetType = layers.EthernetTypeIPv4

	ip, _ := h.privateNetworkIP()
	ip4 := &layers.IPv4{}
	ip4.SrcIP = net.ParseIP(ip)
	ip4.DstIP = net.ParseIP(destination)
	ip4.Version = 4
	ip4.TTL = 64
	ip4.Protocol = layers.IPProtocolTCP

	tcp := &layers.TCP{}
	tcp.SrcPort = 444
	tcp.DstPort = 8070
	tcp.ACK = true
	tcp.PSH = true
	tcp.Window = 400
	tcp.Seq = 1
	tcp.SetNetworkLayerForChecksum(ip4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{true, true}
	err = gopacket.SerializeLayers(buf, opts, eth, ip4, tcp, gopacket.Payload(packet))
	if err != nil {
		log.Println("gopacket:", err)
		return err
	}

	//err = c.raw.Write( buf.Bytes() )
	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		log.Println("Pcap Error:", err)
	}
	time.Sleep(time.Millisecond * 10)
	return err

}

func (h *HackathonNetworkRot) Start() {
	fmt.Println("hello world")
	destination := "192.168.141.255"

	// Setup Pcap
	pcapHandle, err := pcap.OpenLive("en0", 65536, true, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
	}

	for {
		h.SendPacket(destination, []byte("ROT13"), pcapHandle)
		time.Sleep(time.Second * 7)
	}
}
