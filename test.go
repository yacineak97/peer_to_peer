package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	_, myIPv4Addr := listenUDPIPv4(3466)
	_, myIPv6Addr := listenUDPIPv6(8994)

	// udpAddress.IP = net.ParseIP(udpAddrs[i].Ip)

	x := formatRemoteNatAddress(&myIPv4Addr)
	fmt.Println(x)
	fmt.Println(int(x[6])<<8 | int(x[7]))

	x = formatRemoteNatAddress(&myIPv6Addr)
	fmt.Println(int(x[18])<<8 | int(x[19]))

	// y := hex.EncodeToString(x[:16])

	// fmt.Println(y)
	// ipv6Addr := net.UDPAddr{IP: net.ParseIP(string(ipv6Bytes))}
	ip := net.IP(net.IP.To16(x[2:18]))
	ipv6Addr := net.UDPAddr{IP: ip}
	fmt.Println(ipv6Addr.IP.String())
	fmt.Println(myIPv6Addr.IP)
}

func formatRemoteNatAddress(ipAndPort *net.UDPAddr) []byte {
	// IPv4
	if ipAndPort.IP.To4() != nil {

		datagram := make([]byte, 8)
		datagram[1] = byte(6)
		copy(datagram[2:6], ipAndPort.IP)
		copy(datagram[6:8], []byte{byte(ipAndPort.Port >> 8), byte(ipAndPort.Port - (ipAndPort.Port>>8)<<8)})
		return datagram
	}

	//IPv6
	if ipAndPort.IP.To4() == nil {
		datagram := make([]byte, 20)
		datagram[1] = byte(18)
		copy(datagram[2:18], ipAndPort.IP)
		copy(datagram[18:20], []byte{byte(ipAndPort.Port >> 8), byte(ipAndPort.Port - (ipAndPort.Port>>8)<<8)})
		return datagram
	}
	return nil
}

func listenUDPIPv4(IPv4Port int) (*net.UDPConn, net.UDPAddr) {
	myIPv4Addr := net.UDPAddr{
		Port: IPv4Port,
		IP:   getLocalIPv4(),
	}

	sockIpv4, _ := net.ListenUDP("udp", &myIPv4Addr)

	if myIPv4Addr.IP == nil {
		fmt.Println("No IPv4 address available in your machine")
		sockIpv4.Close()
		sockIpv4 = nil
	}

	return sockIpv4, myIPv4Addr
}

func getLocalIPv4() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Println(err)
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func listenUDPIPv6(IPv6Port int) (*net.UDPConn, net.UDPAddr) {
	myIPv6Addr := net.UDPAddr{
		Port: IPv6Port,
		IP:   getLocalIPv6(),
	}

	sockIpv6, _ := net.ListenUDP("udp6", &myIPv6Addr)

	if myIPv6Addr.IP == nil {
		fmt.Print("No IPv6 address available in your machine \n\n")
		sockIpv6.Close()
		sockIpv6 = nil
	}

	return sockIpv6, myIPv6Addr
}

func getLocalIPv6() net.IP {
	conn, err := net.Dial("udp6", "[2001:4860:4860:0:0:0:0:8888]:53")
	if err != nil {
		log.Println(err)
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}
