package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"strconv"
	"time"
)

type MerkleTree struct {
	Root           *Node
	merkleRootHash [32]byte
}

type Node struct {
	// typeNode int
	hash [32]byte
	sons []*Node

	leaf    bool
	content []byte
}

func main() {
	// sum := sha256.Sum256([]byte("hello world\n"))
	// fmt.Println(sum)

	var datagrams [][]byte
	var msgs [33]string

	for i := 0; i < 33; i++ {
		var datagram [1024]byte
		msgs[i] = "Message " + strconv.Itoa(i+1)
		datagram = getFormatedMsg(datagram, 0, time.Now().Unix(), nil, []byte(msgs[i]))
		datagrams = append(datagrams, datagram[:])
	}

	var leafs []*Node

	for _, v := range datagrams {
		node := &Node{
			hash:    sha256.Sum256(v),
			leaf:    true,
			content: v,
		}

		leafs = append(leafs, node)
	}

	root := buildMerkleTree(leafs)

	hash := root.sons[1].hash

	fmt.Println(hash)

	msg := getSons(root, hash)

	fmt.Println(msg)

}

func getSons(node *Node, hash [32]byte) []byte {
	if reflect.DeepEqual(node.hash, hash) {
		return node.content
	} else {

		for j := 0; j < len(node.sons); j++ {
			content := getSons(node.sons[j], hash)
			if content != nil {
				return content
			}
		}
	}
	return nil
}

func getFormatedMsg(datagram [1024]byte, typeMsg byte, date int64, inReplyTo []byte, body []byte) [1024]byte {
	datagram[0] = typeMsg
	dateByte := []byte{byte(date >> 24), byte(date>>16 - (date>>24)<<8), byte(date>>8 - (date>>16)<<8), byte(date - (date>>24)<<8)}
	copy(datagram[1:5], dateByte)
	length := len(body)
	copy(datagram[37:39], []byte{byte(length >> 8), byte(length - (length>>8)<<8)})
	copy(datagram[39:], body)

	return datagram

}

func buildMerkleTree(nodesDownLevel []*Node) *Node {
	var nodeUpLevel []*Node

	emptyNode := &Node{
		hash: sha256.Sum256([]byte{}),
	}

	if len(nodesDownLevel)%32 == 1 {
		nodesDownLevel = append(nodesDownLevel, emptyNode)
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
	}
	return buildMerkleTree(nodeUpLevel)
}
