package main

import (
	"crypto/sha256"
	"fmt"
)

type MerkleTree struct {
	Root       *Node
	merkleRoot []byte
	sons       []*Node
}

type Node struct {
	// typeNode int
	hash [32]byte
	sons []*Node

	leaf    bool
	content string
}

func main() {
	// var root MerkleTree
	sum := sha256.Sum256([]byte("hello world\n"))
	fmt.Println(sum)
	// fmt.Println(sha256.Sum256({}))
	sum = sha256.Sum256([]byte{})
	fmt.Println(sum)
	sum = sha256.Sum256([]byte{})
	fmt.Println(sum)

	chash := []byte{1}
	chash = append(chash, []byte{2, 3, 44, 5}...)

	fmt.Println(chash)
}
