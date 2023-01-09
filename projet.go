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
	"os"
	"reflect"
	"sync"
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

type nameAndKeyJson struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

func main() {
	// var rootMsg []byte
	sizeMsg := 1128
	datagram := make([]byte, sizeMsg)
	flag := make([]byte, 4)
	username := "com4"
	usernameByte := []byte(username)
	id := []byte{34, 122, 76, 97}
	IPv4Port := 7554
	IPv6Port := 3994
	sockIpv4, _ := listenUDPIPv4(IPv4Port)
	sockIpv6, myIPv6Addr := listenUDPIPv6(IPv6Port)
	var wg sync.WaitGroup

	client := getClient()

	privateKey, _, keyBase64 := generatePrivateAndPublicKey()

	registerInServer(username, keyBase64, client)

	udpServerAddresses := getUDPAddrArray(getUdpServerAddrs(client))

	fmt.Println(udpServerAddresses)

	/////////////////////////////////////////////////////////////////////////////////////////////////////
	// say hello to SERVER
	// IPV4

	go replyAllPeers(usernameByte, flag, sizeMsg, privateKey, sockIpv4, &wg)
	go replyAllPeers(usernameByte, flag, sizeMsg, privateKey, sockIpv6, &wg)
	datagram = buildDatagram(id, 0, flag, usernameByte, nil, sizeMsg, privateKey)

	wg.Add(1)
	sayHello(datagram, id, sockIpv4, udpServerAddresses[0], &wg)

	// IPV6

	if myIPv6Addr.IP != nil {
		datagram = buildDatagram(id, 0, flag, usernameByte, nil, sizeMsg, privateKey)
		sayHello(datagram, id, sockIpv6, udpServerAddresses[1], &wg)

	}

	// /////////////////////////////////////////////////////////////////////////////////////////////////////
	// say hello to PEER

	body := getRequest(client, "https://jch.irif.fr:8443/peers")

	fmt.Println(string(body))

	// body = getRequest(client, "https://jch.irif.fr:8443/peers/jch")

	// var peerInfo peerInfoJson
	// if err := json.Unmarshal(body, &peerInfo); err != nil {
	// 	log.Fatal(err)
	// }

	// peerUdpAddresses := getUDPAddrArray(peerInfo.Addresses)

	// // IPV4
	// datagram = buildDatagram(id, 0, flag, usernameByte, nil, sizeMsg, privateKey)

	// sayHello(datagram, id, sockIpv4, peerUdpAddresses[0])

	// // IPV6
	// datagram = buildDatagram(id, 0, flag, usernameByte, nil, sizeMsg, privateKey)

	// if myIPv6Addr.IP != nil {
	// 	sayHello(datagram, id, sockIpv6, peerUdpAddresses[1])
	// }

	// //////////////////////////////////////////////////////////////////////////////////////////////
	// // RootRequest PEER
	// datagram = buildDatagram(id, 1, nil, nil, nil, sizeMsg, nil)

	// rootRequest(datagram, id, sockIpv4, peerUdpAddresses[0])

	// //////////////////////////////////////////////////////////////////////////////////////////////
	// // send Datum

	// root := datagram[7:39]
	// recursiveMircle(datagram, peerUdpAddresses[0], sockIpv4, root, id, sizeMsg)

	// ///////////////////////////////////////////////////////
	// // NAT

}

func recursiveMircle(datagram []byte, peerAddress net.UDPAddr, sock *net.UDPConn, hash []byte, id []byte, sizeMsg int) {
	datagram = buildDatagram(id, 2, nil, nil, hash, sizeMsg, nil)

	_, err := sock.WriteToUDP(datagram, &peerAddress)
	if err != nil {
		log.Fatal("sockIpv4.WriteToUDP >> ", err)
	}

	sock.SetReadDeadline(time.Now().Add(time.Duration(5) * time.Second))

	sock.ReadFromUDP(datagram)

	if datagram[39] == 0 {
		lengthMsg := int(datagram[76])<<8 | int(datagram[77])
		a := datagram[78 : 78+lengthMsg]
		timestamp := int64(datagram[40])<<24 | int64(datagram[41])<<16 | int64(datagram[42])<<8 | int64(datagram[43])
		publishDate := time.Unix(timestamp, 0)
		fmt.Println(string(a))
		fmt.Println("\tPublished in : ", publishDate)
		return
	}

	if datagram[4] == 131 {
		fmt.Println("No Datum")
		return
	}

	if datagram[39] != 0 && datagram[39] != 1 {
		return
	}

	length := int(datagram[5])<<8 | int(datagram[6])
	numberOfHashNodes := len(datagram[40:length+7]) / 32
	i := 0
	for i <= numberOfHashNodes {
		recursiveMircle(datagram, peerAddress, sock, datagram[40+i*32:40+i*32+32], id, sizeMsg)
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

func replyAllPeers(usernameByte []byte, flag []byte, sizeMsg int, privateKey *ecdsa.PrivateKey, sock *net.UDPConn, wg *sync.WaitGroup) {
	if sock == nil {
		return
	}

	for {
		wg.Wait()
		replyToPeer(usernameByte, flag, sizeMsg, privateKey, sock)
	}
}

func replyToPeer(usernameByte []byte, flag []byte, sizeMsg int, privateKey *ecdsa.PrivateKey, sock *net.UDPConn) {
	if sock == nil {
		return
	}
	n := 0
	receivedDatagram := make([]byte, sizeMsg)

	n, peerUdpAddress, err := sock.ReadFromUDP(receivedDatagram)
	if err != nil {
		log.Println("ERROR replyAllPeers func >> ", err)
	}

	if n != 0 && receivedDatagram[4] == 0 {
		id := receivedDatagram[0:3]
		receivedDatagram = make([]byte, 100)

		// buildDatagram(id, username, nil, 0, length)
		copy(receivedDatagram[0:3], id)
		copy(receivedDatagram[4:12], []byte{128, 0, 15, 14, 3, 122, 14, byte(len(usernameByte))})
		copy(receivedDatagram[12:12+len(usernameByte)], usernameByte)
		receivedDatagram = buildDatagram(id, 128, flag, usernameByte, nil, sizeMsg, privateKey)

		_, err = sock.WriteToUDP(receivedDatagram, peerUdpAddress)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func sayHello(helloMsg []byte, id []byte, sock *net.UDPConn, udpAddress net.UDPAddr, wg *sync.WaitGroup) {
	exponent := 0

	for helloMsg[4] != 128 || !reflect.DeepEqual(helloMsg[0:len(id)], id) {
		deadLineTime := math.Pow(2, float64(exponent))
		exponent += 1
		if deadLineTime > 64 {
			fmt.Println("Timeout : No HelloReply Recieved")
			os.Exit(1)
		}

		if helloMsg[4] == 254 {
			length := int(helloMsg[5])<<8 | int(helloMsg[6])
			fmt.Println("recievedHelloReply >> ", string(helloMsg[7:7+length]))
		}

		if helloMsg[4] != 128 || !reflect.DeepEqual(helloMsg[0:len(id)], id) {
			_, err := sock.WriteToUDP(helloMsg, &udpAddress)
			if err != nil {
				log.Fatal(err)
			}
		}

		sock.SetReadDeadline(time.Now().Add(time.Duration(deadLineTime) * time.Second))

		_, _, err := sock.ReadFromUDP(helloMsg)
		fmt.Println(helloMsg)

		if err != nil {
			log.Println("ERROR >>", err)
		}

		sock.SetReadDeadline(time.Time{})
	}
	wg.Done()
}

func rootRequest(rootMsg []byte, id []byte, sock *net.UDPConn, udpAddress net.UDPAddr) {
	exponent := 0
	for rootMsg[4] != 129 || !reflect.DeepEqual(rootMsg[0:len(id)], id) {
		deadLineTime := math.Pow(2, float64(exponent))
		exponent += 1
		if deadLineTime > 64 {
			fmt.Println("Timeout : No Root Recieved")
			os.Exit(1)
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
}

func buildDatagram(id []byte, typeMsg int, flag []byte, usernameByte []byte, hash []byte, sizeMsg int, privateKey *ecdsa.PrivateKey) []byte {
	if typeMsg == 0 || typeMsg == 128 { // hello or helloReply
		datagram := make([]byte, sizeMsg)
		length := 5 + len(usernameByte)
		copy(datagram[0:len(id)], id)
		datagram[4] = byte(typeMsg)
		copy(datagram[5:7], []byte{byte(length >> 8), byte(length - (length>>8)<<8)})
		copy(datagram[7:11], flag)
		datagram[11] = byte(len(usernameByte))
		copy(datagram[12:12+len(usernameByte)], usernameByte)

		signature := getMsgSignature(datagram, privateKey)

		copy(datagram[7+length:], signature)

		datagram = datagram[:64+7+length]

		return datagram

	} else if typeMsg == 1 { // RootRequest message
		datagram := make([]byte, sizeMsg)
		copy(datagram[0:len(id)], id)
		datagram[4] = byte(typeMsg)

		return datagram

	} else if typeMsg == 2 { // GetDatum type message
		datagram := make([]byte, sizeMsg)
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

func getLocalIPv4() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
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

func getUdpServerAddrs(client *http.Client) []udpAddrJson {
	body := getRequest(client, "https://jch.irif.fr:8443/udp-address")

	var serverUdpAddrsJson []udpAddrJson
	if err := json.Unmarshal(body, &serverUdpAddrsJson); err != nil {
		log.Fatal(err)
	}

	return serverUdpAddrsJson
}

func registerInServer(name string, keyBase64 string, client *http.Client) {
	nameAndKey := nameAndKeyJson{
		Name: name,
		Key:  keyBase64,
	}

	body, _ := json.Marshal(nameAndKey)

	req, err := http.NewRequest("POST", "https://jch.irif.fr:8443/register", bytes.NewBuffer(body))
	if err != nil {
		log.Fatal(err)
	}

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(res)
}

func generatePrivateAndPublicKey() (*ecdsa.PrivateKey, *ecdsa.PublicKey, string) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	publicKey, ok := privateKey.Public().(*ecdsa.PublicKey)
	fmt.Println("Private Key generated successfully", ok)
	formatted := make([]byte, 64)
	publicKey.X.FillBytes(formatted[:32])
	publicKey.Y.FillBytes(formatted[32:])
	keyBase64 := base64.RawStdEncoding.EncodeToString(formatted)

	return privateKey, publicKey, keyBase64
}

func getClient() *http.Client {
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	return client
}

func getMsgSignature(datagram []byte, privateKey *ecdsa.PrivateKey) []byte {
	if privateKey != nil {
		signature := make([]byte, 64)
		length := int(datagram[5])<<8 | int(datagram[6])
		hashed := sha256.Sum256(datagram[0 : 7+length])
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])

		if err != nil {
			log.Fatal(err)
		}

		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])

		return signature
	}

	return nil

}

func listenUDPIPv6(IPv6Port int) (*net.UDPConn, net.UDPAddr) {
	myIPv6Addr := net.UDPAddr{
		Port: IPv6Port,
		IP:   getLocalIPv6(),
	}

	sockIpv6, err := net.ListenUDP("udp6", &myIPv6Addr)
	if err != nil {
		log.Fatal(err)
	}

	if myIPv6Addr.IP == nil {
		sockIpv6.Close()
		sockIpv6 = nil
	}

	return sockIpv6, myIPv6Addr
}

func listenUDPIPv4(IPv4Port int) (*net.UDPConn, net.UDPAddr) {
	myIPv4Addr := net.UDPAddr{
		Port: IPv4Port,
		IP:   getLocalIPv4(),
	}

	sockIpv4, err := net.ListenUDP("udp", &myIPv4Addr)
	if err != nil {
		log.Fatal(err)
	}

	if myIPv4Addr.IP == nil {
		sockIpv4.Close()
		sockIpv4 = nil
	}

	return sockIpv4, myIPv4Addr
}
