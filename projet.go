package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"reflect"
	"time"
)

type udpAddrJson struct {
	Ip   string `json:"ip"`
	Port int64  `json:"port"`
}

type peerInfoJson struct {
	Name      string        `json:"name"`
	Addresses []udpAddrJson `json:"addresses"`
	Key       string        `json:"key"`
}

type registerJson struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

func main() {
	// var rootMsg []byte
	var helloMsg []byte
	name := "com2"
	username := []byte(name)
	id := []byte{34, 122, 76, 97}
	length := 9

	// Private and Public key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey, ok := privateKey.Public().(*ecdsa.PublicKey)
	fmt.Println(ok)
	formatted := make([]byte, 64)
	publicKey.X.FillBytes(formatted[:32])
	publicKey.Y.FillBytes(formatted[32:])
	keyBase64 := base64.RawStdEncoding.EncodeToString(formatted)
	fmt.Println(keyBase64)

	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	body := getRequest(client, "https://jch.irif.fr:8443/udp-address")

	var serverUdpAddr []udpAddrJson
	if err := json.Unmarshal(body, &serverUdpAddr); err != nil {
		log.Fatal(err)
	}

	udpServerAddresses := getUDPAddrArray(serverUdpAddr)

	fmt.Println(udpServerAddresses)

	nameKey := []byte(fmt.Sprintf(`{"name":"%s", "key":"%s"}`, name, keyBase64))

	// nameKey := strings.NewReader(`{"name": "computer1"}`)

	req, err := http.NewRequest("POST", "https://jch.irif.fr:8443/register", bytes.NewBuffer(nameKey))
	if err != nil {
		log.Fatal(err)
	}

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(res)

	/////////////////////////////////////////////////////////////////////////////////////////////////////
	// send hello to SERVER
	// IPV4
	addr := net.UDPAddr{
		Port: 5658,
		IP:   net.ParseIP("192.168.164.96"),
	}

	sockIpv4, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatal(err)
	}

	helloMsg = buildDatagram(id, username, nil, 0, length)
	fmt.Println(helloMsg[:7+length])
	hashed := sha256.Sum256(helloMsg[0 : 7+length])
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	copy(helloMsg[7+length:], signature)

	helloMsg = helloMsg[:64+7+length]
	if !recievedHelloReply(helloMsg, id, sockIpv4, udpServerAddresses[0]) {
		fmt.Println("Didn't receive helloReply from server (IPV4)")
		return
	}

	replyAllPeers(username, length, sockIpv4, udpServerAddresses[0])

	// IPV6
	addr = net.UDPAddr{
		Port: 8564,
		IP:   net.ParseIP("2a01:cb01:2051:9ab1:7691:8c04:2e37:e85f"),
	}

	sockIpv6, err := net.ListenUDP("udp6", &addr)
	if err != nil {
		log.Fatal(err)
	}

	helloMsg = buildDatagram(id, username, nil, 0, length)

	if !recievedHelloReply(helloMsg, id, sockIpv6, udpServerAddresses[1]) {
		fmt.Println("Didn't receive helloReply from server (IPV6)")
		return
	}

	replyAllPeers(username, length, sockIpv6, udpServerAddresses[1])

	// /////////////////////////////////////////////////////////////////////////////////////////////////////
	// // send hello to peer

	// body = getRequest(client, "https://jch.irif.fr:8443/peers")

	// fmt.Println(string(body))

	// body = getRequest(client, "https://jch.irif.fr:8443/peers/jch")

	// var peerInfo peerInfoJson
	// if err := json.Unmarshal(body, &peerInfo); err != nil {
	// 	log.Fatal(err)
	// }

	// peerUdpAddresses := getUDPAddrArray(peerInfo.Addresses)

	// // IPV4

	// helloMsg = buildDatagram(id, username, nil, 0, length)

	// if !recievedHelloReply(helloMsg, id, sockIpv4, peerUdpAddresses[0]) {
	// 	fmt.Println("Didn't receive helloReply from jch (IPV4)")
	// 	return
	// }

	// replyAllPeers(username, length, sockIpv4, peerUdpAddresses[0])

	// // IPV6

	// helloMsg = buildDatagram(id, username, nil, 0, length)

	// if !recievedHelloReply(helloMsg, id, sockIpv6, peerUdpAddresses[1]) {
	// 	fmt.Println("Didn't receive helloReply from jch (IPV6)")
	// 	return
	// }

	// replyAllPeers(username, length, sockIpv6, peerUdpAddresses[1])

	// //////////////////////////////////////////////////////////////////////////////////////////////
	// // send RootRequest
	// rootMsg = buildDatagram(id, nil, nil, 1, 0)

	// if !recieveRoot(rootMsg, id, sockIpv4, peerUdpAddresses[0]) {
	// 	fmt.Println("Didn't receive helloReply from jch (IPV6)")
	// 	return
	// }

	// //////////////////////////////////////////////////////////////////////////////////////////////
	// // send Datum

	// recursiveMircle(peerUdpAddresses[0], sockIpv4, rootMsg[7:39], id)

	// ///////////////////////////////////////////////////////
	// // NAT

}

func recursiveMircle(peerAddress net.UDPAddr, sock *net.UDPConn, hash []byte, id []byte) {
	datumMsg := buildDatagram(id, nil, hash, 2, 32)

	_, err := sock.WriteToUDP(datumMsg, &peerAddress)
	if err != nil {
		log.Fatal("sockIpv4.WriteToUDP >> ", err)
	}

	sock.SetReadDeadline(time.Now().Add(time.Duration(5) * time.Second))

	sock.ReadFromUDP(datumMsg)

	if datumMsg[39] == 0 {
		lengthMsg := int(datumMsg[76])<<8 | int(datumMsg[77])
		a := datumMsg[78 : 78+lengthMsg]
		fmt.Println(string(a))
		return
	}

	if datumMsg[4] == 131 {
		fmt.Println("No Datum")
		return
	}

	if datumMsg[39] != 0 && datumMsg[39] != 1 {
		return
	}

	length := int(datumMsg[5])<<8 | int(datumMsg[6])
	numberOfHashNodes := len(datumMsg[40:length+7]) / 32
	i := 0
	for i <= numberOfHashNodes {
		recursiveMircle(peerAddress, sock, datumMsg[40+i*32:40+i*32+32], id)
		i += 1
	}
}

func getRequest(client *http.Client, url string) []byte {
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		log.Fatal(err)
	}

	response, err := client.Do(req)

	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(response.Body)

	if err != nil {
		log.Fatal(err)
	}

	return body
}

func replyAllPeers(username []byte, length int, sock *net.UDPConn, udpAddress net.UDPAddr) {
	// for {
	n := 0
	receivedDatagram := make([]byte, 100)
	sock.SetReadDeadline(time.Now().Add(time.Duration(2) * time.Second))
	n, _, err := sock.ReadFromUDP(receivedDatagram)
	if err != nil {
		log.Println("ERROR replyAllPeers func >> ", err)
	}

	if n != 0 && receivedDatagram[4] == 0 {
		id := receivedDatagram[0:3]
		receivedDatagram = make([]byte, 100)

		// buildDatagram(id, username, nil, 0, length)
		copy(receivedDatagram[0:3], id)
		copy(receivedDatagram[4:12], []byte{128, 0, 15, 14, 3, 122, 14, byte(len(username))})
		copy(receivedDatagram[12:12+len(username)], username)

		_, err = sock.WriteToUDP(receivedDatagram, &udpAddress)
		if err != nil {
			log.Fatal(err)
		}
	}

	// }

}

func recievedHelloReply(helloMsg []byte, id []byte, sock *net.UDPConn, udpAddress net.UDPAddr) bool {
	exponent := 0
	for helloMsg[4] != 128 || !reflect.DeepEqual(helloMsg[0:len(id)], id) {
		deadLineTime := math.Pow(2, float64(exponent))
		exponent += 1
		if deadLineTime > 64 {
			fmt.Println("Timeout : No HelloReply Recieved")
			return false
		}

		if helloMsg[4] == 254 {
			length := int(helloMsg[5])<<8 | int(helloMsg[6])
			fmt.Println("recievedHelloReply >> ", string(helloMsg[7:7+length]))
			return false
		}
		if helloMsg[4] != 128 || !reflect.DeepEqual(helloMsg[0:len(id)], id) {
			_, err := sock.WriteToUDP(helloMsg, &udpAddress)
			if err != nil {
				log.Fatal(err)
			}
		}

		sock.SetReadDeadline(time.Now().Add(time.Duration(deadLineTime) * time.Second))

		_, _, err := sock.ReadFromUDP(helloMsg)
		if err != nil {
			log.Println("ERROR >>", err)
		}

		sock.SetReadDeadline(time.Time{})
	}
	return true
}

func recieveRoot(rootMsg []byte, id []byte, sock *net.UDPConn, udpAddress net.UDPAddr) bool {
	exponent := 0
	for rootMsg[4] != 129 || !reflect.DeepEqual(rootMsg[0:len(id)], id) {
		deadLineTime := math.Pow(2, float64(exponent))
		exponent += 1
		if deadLineTime > 64 {
			fmt.Println("Timeout : No Root Recieved")
			return false
		}

		fmt.Println("recieveRoot >> ", string(rootMsg))

		if rootMsg[4] != 129 || !reflect.DeepEqual(rootMsg[0:len(id)], id) {
			_, err := sock.WriteToUDP(rootMsg, &udpAddress)
			if err != nil {
				log.Fatal(err)
			}
		}

		sock.SetReadDeadline(time.Now().Add(time.Duration(deadLineTime) * time.Second))

		_, _, err := sock.ReadFromUDP(rootMsg)
		if err != nil {
			log.Println("ERROR >>", err)
		}
		sock.SetReadDeadline(time.Time{})
	}
	return true
}

func buildDatagram(id []byte, username []byte, hash []byte, typeMsg int, length int) []byte {
	if typeMsg == 0 || typeMsg == 128 { // hello or helloReply
		datagram := make([]byte, 100)
		copy(datagram[0:len(id)], id)
		datagram[4] = byte(typeMsg)
		copy(datagram[5:12], []byte{byte(length >> 8), byte(length - (length>>8)<<8), 0, 0, 0, 0, byte(len(username))})
		copy(datagram[12:12+len(username)], username)

		return datagram
	} else if typeMsg == 1 { // RootRequest message
		datagram := make([]byte, 200)
		copy(datagram[0:len(id)], id)
		datagram[4] = byte(typeMsg)

		return datagram
	} else if typeMsg == 2 { // Datum type message a
		datagram := make([]byte, 1200)
		copy(datagram[0:len(id)], id)
		datagram[4] = byte(typeMsg)
		datagram[6] = 32
		copy(datagram[7:39], hash)

		return datagram
	}

	return nil

}

func getUDPAddrArray(udpAddrs []udpAddrJson) []net.UDPAddr {
	udpAddresses := make([]net.UDPAddr, 0)
	var udpAddress net.UDPAddr

	i := 0
	for i < len(udpAddrs) {
		udpAddress.Port = int(udpAddrs[i].Port)
		udpAddress.IP = net.ParseIP(udpAddrs[i].Ip)
		udpAddresses = append(udpAddresses, udpAddress)
		i += 1
	}

	return udpAddresses
}
