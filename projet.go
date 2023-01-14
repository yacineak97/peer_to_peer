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
	"strconv"
	"strings"
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

type Node struct {
	// typeNode int
	hash [32]byte
	sons []*Node

	leaf    bool
	content []byte
}

func main() {
	sizeMsg := 1128
	datagram := make([]byte, sizeMsg)
	flag := make([]byte, 4)
	username := "com4"
	usernameByte := []byte(username)
	id := []byte{34, 122, 76, 97}
	IPv4Port := 8777
	IPv6Port := 7888
	sockIpv4, myIPv4Addr := listenUDPIPv4(IPv4Port)
	sockIpv6, myIPv6Addr := listenUDPIPv6(IPv6Port)
	channel := make(chan []byte)
	myMsgNumber := 33

	if myIPv4Addr.IP == nil && myIPv6Addr.IP == nil {
		fmt.Println("No IPv4 and IPv6 address available in your machine ")
		os.Exit(1)
	}

	// build merkel tree
	myMessagesByte := getMyMessages(myMsgNumber)
	leaves := getMerkleLeaves(myMessagesByte)
	rootMerkel := buildMerkleTree(leaves)

	// // that's how to append a message to Merkle tree
	// messageToAppend := getMyMessage(34)
	// myMessagesByte = append(myMessagesByte, messageToAppend)
	// leaves = getMerkleLeaves(myMessagesByte)
	// rootMerkel = buildMerkleTree(leaves)

	client := getClient()
	privateKey, _, keyBase64 := generatePrivateAndPublicKey()
	registerInServer(username, keyBase64, client)
	udpServerAddresses := getUDPAddrArray(getUdpServerAddrs(client))

	// Reply to every received request from any peer
	go replyAllPeers(usernameByte, flag, sizeMsg, privateKey, rootMerkel, sockIpv4, channel)
	go replyAllPeers(usernameByte, flag, sizeMsg, privateKey, rootMerkel, sockIpv6, channel)

	// Say hello to server in IPv4 and IPv6
	datagram = buildDatagram(id, 0, flag, usernameByte, nil, nil, sizeMsg, privateKey)
	sayHelloToPeer(datagram, udpServerAddresses, sockIpv4, myIPv4Addr, sockIpv6, myIPv6Addr, channel)

	// choose a peer
	peerUdpAddresses := getPeerAddresses(client)

	// say hello to peer in IPv4 and IPv6
	datagram = buildDatagram(id, 0, flag, usernameByte, nil, nil, sizeMsg, privateKey)
	sayHelloToPeer(datagram, peerUdpAddresses, sockIpv4, myIPv4Addr, sockIpv6, myIPv6Addr, channel)

	// RootRequest peer
	datagram = buildDatagram(id, 1, nil, nil, nil, nil, sizeMsg, nil)
	datagram = rootRequestToPeer(datagram, peerUdpAddresses, sockIpv4, myIPv4Addr, sockIpv6, myIPv6Addr, channel)

	// send Datum
	rootPeerHash := datagram[7:39]
	rootMerkelPeer := new(Node)

	// var rootPeerMercle *Node
	getMerkleMsgsFromPeer(rootMerkelPeer, peerUdpAddresses[0], sockIpv4, rootPeerHash, id, sizeMsg, channel)

	for {
		datagram = buildDatagram(id, 1, nil, nil, nil, nil, sizeMsg, nil)
		datagram = rootRequestToPeer(datagram, peerUdpAddresses, sockIpv4, myIPv4Addr, sockIpv6, myIPv6Addr, channel)
		newRootPeer := datagram[7:39]
		if !reflect.DeepEqual(rootPeerHash[:], newRootPeer) {
			getMerkleMsgsFromPeer(rootMerkelPeer, peerUdpAddresses[0], sockIpv4, newRootPeer, id, sizeMsg, channel)
			rootPeerHash = newRootPeer
		}
	}

	///////////////////////////////////////////////////////
	// NAT

}

func getMerkleMsgsFromPeer(node *Node, peerAddress net.UDPAddr, sock *net.UDPConn, hash []byte, id []byte, sizeMsg int, channel chan []byte) {
	exponent := 0
	datagram := buildDatagram(id, 2, nil, nil, hash, nil, sizeMsg, nil)

	for (datagram[4] != 130 || !reflect.DeepEqual(datagram[0:len(id)], id)) &&
		(datagram[4] != 131 || !reflect.DeepEqual(datagram[0:len(id)], id)) {

		datagram = buildDatagram(id, 2, nil, nil, hash, nil, sizeMsg, nil)

		deadLineTime := math.Pow(2, float64(exponent))
		exponent += 1
		if deadLineTime > 64 {
			fmt.Println("Timeout : Peer not responding")
			os.Exit(1)
		}

		if datagram[4] == 254 {
			length := int(datagram[5])<<8 | int(datagram[6])
			fmt.Println("getMerkleMsgsFromPeer error >> ", string(datagram[7:7+length]))
		}

		if (datagram[4] != 130 || !reflect.DeepEqual(datagram[0:len(id)], id)) &&
			(datagram[4] != 130 || !reflect.DeepEqual(datagram[0:len(id)], id)) {
			_, err := sock.WriteToUDP(datagram, &peerAddress)
			if err != nil {
				log.Fatal("sockIpv4.WriteToUDP >> ", err)
			}
		}

		sock.SetReadDeadline(time.Now().Add(time.Duration(int(deadLineTime)) * time.Second))
		datagram = <-channel
		sock.SetReadDeadline(time.Time{})
	}

	// verify hash is correct
	length := int(datagram[5])<<8 | int(datagram[6])
	calculatedHash := sha256.Sum256(datagram[7+32 : length+7])
	if !reflect.DeepEqual(datagram[7:7+32], calculatedHash[:]) && datagram[4] != 131 {
		log.Println("Received wrong hash value from peer")
		os.Exit(1)
	}

	if datagram[4] == 130 && datagram[39] == 0 {
		if node.hash == new(Node).hash {
			var hashCorr [32]byte
			content := datagram[39 : length+7]
			copy(hashCorr[:], hash)

			node.hash = hashCorr
			node.content = content
			node.leaf = true

			lengthMsg := int(datagram[76])<<8 | int(datagram[77])
			msg := datagram[78 : 78+lengthMsg]
			timestamp := int64(datagram[40])<<24 | int64(datagram[41])<<16 | int64(datagram[42])<<8 | int64(datagram[43])
			publishDate := time.Unix(timestamp, 0)
			fmt.Println(string(msg))
			fmt.Println("\tPublished in : ", publishDate)
			fmt.Println("\tReplies to ", datagram[44:44+32])

		} else if !reflect.DeepEqual(node.hash[:], hash) {
			var hashCorr [32]byte
			copy(hashCorr[:], hash)

			node.hash = hashCorr
			node.content = datagram[39 : length+7]
			node.leaf = true

			lengthMsg := int(datagram[76])<<8 | int(datagram[77])
			msg := datagram[78 : 78+lengthMsg]
			timestamp := int64(datagram[40])<<24 | int64(datagram[41])<<16 | int64(datagram[42])<<8 | int64(datagram[43])
			publishDate := time.Unix(timestamp, 0)
			fmt.Println(string(msg))
			fmt.Println("\tPublished in : ", publishDate)
			fmt.Println("\tReplies to ", datagram[44:44+32])
		}
		return
	}

	if datagram[4] == 131 {
		fmt.Println("No Datum")
		return
	}

	if datagram[4] == 130 && datagram[39] != 0 && datagram[39] != 1 {
		return
	}

	if datagram[4] == 130 && datagram[39] == 1 {
		length := int(datagram[5])<<8 | int(datagram[6])
		numberOfHashNodes := len(datagram[40:length+7]) / 32
		if node.hash == new(Node).hash {
			var hashCorr [32]byte
			copy(hashCorr[:], hash)

			s := make([]*Node, numberOfHashNodes)
			for i := range s {
				s[i] = new(Node)
			}

			node.hash = hashCorr
			node.content = datagram[39 : length+7]
			node.leaf = false
			node.sons = s

			i := 0
			for i < numberOfHashNodes {
				getMerkleMsgsFromPeer(node.sons[i], peerAddress, sock, datagram[40+i*32:40+i*32+32], id, sizeMsg, channel)
				i += 1
			}

		} else if !reflect.DeepEqual(node.hash[:], hash) {
			var hashCorr [32]byte
			copy(hashCorr[:], hash)

			node.content = datagram[39 : length+7]
			node.hash = hashCorr
			node.leaf = false

			if len(node.sons) < numberOfHashNodes {
				s := make([]*Node, numberOfHashNodes-len(node.sons))
				for i := range s {
					s[i] = new(Node)
				}
				node.sons = append(node.sons, s...)
			}

			i := 0
			for i < numberOfHashNodes {
				if !reflect.DeepEqual(node.sons[i].hash[:], datagram[40+i*32:40+i*32+32]) {
					getMerkleMsgsFromPeer(node.sons[i], peerAddress, sock, datagram[40+i*32:40+i*32+32], id, sizeMsg, channel)
				}
				i += 1
			}
		}
	}
}

func buildMerkleTree(nodesDownLevel []*Node) *Node {
	var nodeUpLevel []*Node

	if len(nodesDownLevel) < 1 {
		fmt.Println("Cannot create merkle tree of empty nodes")
		return nil
	}

	if len(nodesDownLevel) == 1 {
		return nodesDownLevel[0]
	}

	for i := 0; i < len(nodesDownLevel); i += 32 {
		chash := []byte{1}
		lastMember := 0
		for j := i; j < i+32 && j < len(nodesDownLevel); j++ {
			chash = append(chash, nodesDownLevel[j].hash[:]...)
			lastMember = j
		}

		nodeNew := &Node{
			hash:    sha256.Sum256(chash),
			sons:    nodesDownLevel[i : lastMember+1],
			content: chash,
			leaf:    false,
		}

		nodeUpLevel = append(nodeUpLevel, nodeNew)

		if len(nodesDownLevel) <= 32 {
			return nodeNew
		}

		if len(nodesDownLevel[lastMember+1:]) < 32 {
			nodeUpLevel = append(nodeUpLevel, nodesDownLevel[lastMember+1:]...)
			break
		}
	}
	return buildMerkleTree(nodeUpLevel)
}

func getMerkleSons(node *Node, hash [32]byte) []byte {
	if reflect.DeepEqual(node.hash, hash) {

		return node.content
	} else {

		for j := 0; j < len(node.sons); j++ {
			content := getMerkleSons(node.sons[j], hash)
			if content != nil {

				return content
			}
		}
	}

	return nil
}

func getMerkleLeaves(datagrams [][]byte) []*Node {
	var leaves []*Node

	for _, v := range datagrams {
		node := &Node{
			hash:    sha256.Sum256(v),
			leaf:    true,
			content: v,
		}

		leaves = append(leaves, node)
	}

	return leaves
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

func replyAllPeers(usernameByte []byte, flag []byte, sizeMsg int, privateKey *ecdsa.PrivateKey, rootMerkel *Node, sock *net.UDPConn, channel chan []byte) {
	if sock == nil {
		return
	}

	for {
		receivedDatagram := make([]byte, sizeMsg)

		n, peerUdpAddress, err := sock.ReadFromUDP(receivedDatagram)
		if err != nil {
			log.Println("ERROR replyAllPeers func >> ", err)
		}
		sock.SetReadDeadline(time.Time{})

		if receivedDatagram[4] == 128 {
			channel <- receivedDatagram
		}

		if receivedDatagram[4] == 129 {
			channel <- receivedDatagram
		}

		if receivedDatagram[4] == 130 || receivedDatagram[4] == 131 {
			channel <- receivedDatagram
		}

		if n == 0 || receivedDatagram[4] == 254 {
			channel <- receivedDatagram
		}

		if n != 0 && receivedDatagram[4] == 0 {
			id := receivedDatagram[0:3]
			receivedDatagram = buildDatagram(id, 128, flag, usernameByte, nil, nil, sizeMsg, privateKey)

			_, err = sock.WriteToUDP(receivedDatagram, peerUdpAddress)
			if err != nil {
				log.Fatal(err)
			}
		}

		if n != 0 && receivedDatagram[4] == 1 {
			id := receivedDatagram[0:3]
			receivedDatagram = buildDatagram(id, 129, nil, nil, rootMerkel.hash[:], nil, sizeMsg, nil)

			_, err = sock.WriteToUDP(receivedDatagram, peerUdpAddress)
			if err != nil {
				log.Fatal(err)
			}
		}

		if n != 0 && receivedDatagram[4] == 2 {
			var requestedHash [32]byte
			id := receivedDatagram[0:3]
			copy(requestedHash[:], receivedDatagram[7:7+32])

			nodeContent := getMerkleSons(rootMerkel, requestedHash)

			if nodeContent == nil {
				receivedDatagram = buildDatagram(id, 131, nil, nil, requestedHash[:], nil, sizeMsg, nil)
				_, err = sock.WriteToUDP(receivedDatagram, peerUdpAddress)
				if err != nil {
					log.Fatal(err)
				}

			} else {
				receivedDatagram = buildDatagram(id, 130, nil, nil, requestedHash[:], nodeContent, sizeMsg, nil)
				_, err = sock.WriteToUDP(receivedDatagram, peerUdpAddress)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

func sayHelloToPeer(datagram []byte, peerUDPAddresses []net.UDPAddr, sockIpv4 *net.UDPConn, myIPv4Addr net.UDPAddr, sockIpv6 *net.UDPConn, myIPv6Addr net.UDPAddr, channel chan []byte) {
	var helloMsg []byte
	copy(helloMsg[:], datagram[:])

	// IPv4
	if myIPv4Addr.IP != nil {
		for _, v := range peerUDPAddresses {
			if v.IP.To4() != nil {
				sayHello(datagram, datagram[0:4], sockIpv4, v, channel)
			}
		}
	}

	// IPV6
	if myIPv6Addr.IP != nil {
		copy(datagram[:], helloMsg[:])
		for _, v := range peerUDPAddresses {
			if v.IP.To16() != nil {
				sayHello(datagram, datagram[0:4], sockIpv6, v, channel)
			}
		}
	}
}

func sayHello(helloMsg []byte, id []byte, sock *net.UDPConn, udpAddress net.UDPAddr, channel chan []byte) {
	exponent := 0
	helloReplyMsg := helloMsg
	for helloReplyMsg[4] != 128 || !reflect.DeepEqual(helloReplyMsg[0:len(id)], id) {
		deadLineTime := math.Pow(2, float64(exponent))
		exponent += 1
		if deadLineTime > 64 {
			fmt.Println("Timeout : No HelloReply Recieved, Server not responding")
			os.Exit(1)
		}

		if helloReplyMsg[4] == 254 {
			length := int(helloReplyMsg[5])<<8 | int(helloReplyMsg[6])
			fmt.Println("sayHello error >> ", string(helloMsg[7:7+length]))
		}

		if helloReplyMsg[4] != 128 || !reflect.DeepEqual(helloReplyMsg[0:len(id)], id) {
			_, err := sock.WriteToUDP(helloMsg, &udpAddress)
			if err != nil {
				log.Fatal(err)
			}
		}

		sock.SetReadDeadline(time.Now().Add(time.Duration(int(deadLineTime)) * time.Second))

		helloReplyMsg = <-channel

		sock.SetReadDeadline(time.Time{})
	}
}

func rootRequestToPeer(datagram []byte, peerUDPAddresses []net.UDPAddr, sockIpv4 *net.UDPConn, myIPv4Addr net.UDPAddr, sockIpv6 *net.UDPConn, myIPv6Addr net.UDPAddr, channel chan []byte) []byte {
	var rootRequestMsg []byte
	copy(rootRequestMsg[:], datagram[:])
	// IPv4
	if myIPv4Addr.IP != nil {
		for _, v := range peerUDPAddresses {
			if v.IP.To4() != nil {
				datagram = rootRequest(datagram, datagram[0:4], sockIpv4, v, channel)
			}
		}
	}

	// IPV6
	if myIPv6Addr.IP != nil {
		copy(datagram[:], rootRequestMsg[:])
		for _, v := range peerUDPAddresses {
			if v.IP.To16() != nil {
				datagram = rootRequest(datagram, datagram[0:4], sockIpv6, v, channel)
			}
		}
	}

	return datagram
}

func rootRequest(rootRequestMsg []byte, id []byte, sock *net.UDPConn, udpAddress net.UDPAddr, channel chan []byte) []byte {
	exponent := 0
	rootReplyMsg := rootRequestMsg
	for rootReplyMsg[4] != 129 || !reflect.DeepEqual(rootReplyMsg[0:len(id)], id) {
		deadLineTime := math.Pow(2, float64(exponent))
		exponent += 1
		if deadLineTime > 64 {
			fmt.Println("Timeout : No Response from peer about Root Request")
			os.Exit(1)
		}

		if rootReplyMsg[4] == 254 {
			length := int(rootReplyMsg[5])<<8 | int(rootReplyMsg[6])
			fmt.Println("rootRequest error >> ", string(rootReplyMsg[7:7+length]))
		}

		if rootReplyMsg[4] != 129 || !reflect.DeepEqual(rootReplyMsg[0:len(id)], id) {
			_, err := sock.WriteToUDP(rootRequestMsg, &udpAddress)
			if err != nil {
				log.Fatal(err)
			}
		}

		sock.SetReadDeadline(time.Now().Add(time.Duration(deadLineTime) * time.Second))

		rootReplyMsg = <-channel

		sock.SetReadDeadline(time.Time{})
	}

	return rootReplyMsg
}

func buildDatagram(id []byte, typeMsg int, flag []byte, usernameByte []byte, hash []byte, value []byte, sizeMsg int, privateKey *ecdsa.PrivateKey) []byte {

	switch typeMsg {
	case 0, 128: // hello or helloReply
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

	case 1: // RootRequest message
		datagram := make([]byte, sizeMsg)
		copy(datagram[0:len(id)], id)
		datagram[4] = byte(typeMsg)

		return datagram

	case 2, 129, 131: // GetDatum type message OR RootReply OR NoDatum
		datagram := make([]byte, sizeMsg)
		copy(datagram[0:len(id)], id)
		datagram[4] = byte(typeMsg)
		datagram[6] = 32
		copy(datagram[7:39], hash)

		return datagram

	case 130: // Datum
		datagram := make([]byte, sizeMsg)
		copy(datagram[0:len(id)], id)
		datagram[4] = byte(typeMsg)
		length := 32 + len(value)
		copy(datagram[5:7], []byte{byte(length >> 8), byte(length - (length>>8)<<8)})
		copy(datagram[7:7+32], hash)
		copy(datagram[7+32:], value)

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

	if res.StatusCode == 204 {
		fmt.Printf("Server HelloReply %c \n\n", 0x1F64B)
	}

	if res.StatusCode == 400 {
		fmt.Printf("Server already replied you %c \n\n", 0x1F612)
	}
}

func generatePrivateAndPublicKey() (*ecdsa.PrivateKey, *ecdsa.PublicKey, string) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	publicKey, ok := privateKey.Public().(*ecdsa.PublicKey)

	if !ok {
		log.Fatal("Private Key not generated")
	}

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
		fmt.Print("No IPv6 address available in your machine \n\n")
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
		fmt.Println("No IPv4 address available in your machine")
		sockIpv4.Close()
		sockIpv4 = nil
	}

	return sockIpv4, myIPv4Addr
}

func getMyMessages(myMsgNumber int) [][]byte {
	var myMessagesByte [][]byte

	for i := 1; i <= myMsgNumber; i++ {
		myMessageByte := getMyMessage(i)
		myMessagesByte = append(myMessagesByte, myMessageByte[:])
	}

	return myMessagesByte
}

func getMyMessage(i int) []byte {
	var msg string
	var myMessageByte [1024]byte

	msg = "My message number " + strconv.Itoa(i)
	myMessageByte = getFormatedMsg(myMessageByte, 0, time.Now().Unix(), nil, []byte(msg))

	return myMessageByte[:]
}

func getFormatedMsg(myMessageByte [1024]byte, typeMsg byte, date int64, inReplyTo []byte, body []byte) [1024]byte {
	myMessageByte[0] = typeMsg
	dateByte := []byte{byte(date >> 24), byte(date>>16 - (date>>24)<<8), byte(date>>8 - (date>>16)<<8), byte(date - (date>>24)<<8)}
	copy(myMessageByte[1:5], dateByte)
	length := len(body)
	copy(myMessageByte[37:39], []byte{byte(length >> 8), byte(length - (length>>8)<<8)})
	copy(myMessageByte[39:], body)

	return myMessageByte

}

func getPeerAddresses(client *http.Client) []net.UDPAddr {
	body := getRequest(client, "https://jch.irif.fr:8443/peers")

	peersArray := strings.Split(string(body), "\n")
	peersArray = peersArray[:len(peersArray)-1]

	for i, p := range peersArray {
		fmt.Println(i+1, "- ", p)
	}

	var choosedPeer int
	fmt.Println("\nChoose a peer to connect with")
	fmt.Scanln(&choosedPeer)

	body = getRequest(client, "https://jch.irif.fr:8443/peers/"+peersArray[choosedPeer-1])

	var peerInfo peerInfoJson
	if err := json.Unmarshal(body, &peerInfo); err != nil {
		log.Fatal(err)
	}

	peerUdpAddresses := getUDPAddrArray(peerInfo.Addresses)

	return peerUdpAddresses
}
