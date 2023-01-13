package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"time"
)

func main() {

	fmt.Println(getLocalIPv4())

	seconds := 1672095164
	startOf2022 := time.Date(2022, 01, 01, 0, 0, 0, 0, time.Local)
	t := startOf2022.Add(time.Duration(seconds) * time.Second)
	fmt.Println(t.Format("2006-01-02 15:04:05"))

	i, err := strconv.ParseInt("1672095164", 10, 64)
	if err != nil {
		panic(err)
	}
	tm := time.Unix(i, 0)
	fmt.Println(tm)

	length := 345
	x := []byte{byte(length >> 8), byte(length - (length>>8)<<8)}
	y := int(x[0])<<8 | int(x[1])

	fmt.Println((length >> 8) << 8)
	fmt.Println(y)
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
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}
