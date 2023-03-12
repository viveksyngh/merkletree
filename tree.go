package merkletree

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"strings"
)

// MerkleHashTree a general purpose merkle hash tree with support for append
// it also stores the merkle hashes in a tree like structure
type MerkleHashTree struct {
	tree [][][sha256.Size]byte
}

// levels returns levels in a tree given the length of leave nodes
func levels(nodes int) int {
	l := int(math.Log2(float64(nodes)))
	if int(math.Pow(2, float64(l))) != nodes {
		l = l + 2
	} else {
		l = l + 1
	}
	return l
}

// New creates and returns a new merkle hash tree
func New(d [][]byte) *MerkleHashTree {
	leaves := make([][sha256.Size]byte, 0)
	for _, e := range d {
		leaves = append(leaves, leafHash(e))
	}
	l := levels(len(d))
	t := make([][][sha256.Size]byte, l)
	t[0] = leaves
	tree := MerkleHashTree{tree: t}
	tree.buildTree(tree.tree[0], l-1)
	return &tree
}

// leafHash returns hash of a leaf node
func leafHash(input []byte) [sha256.Size]byte {
	e := []byte{LeafPrefix}
	e = append(e, input...)
	return sha256.Sum256(e)
}

// nodeHash returns hash of non leaf node
func nodeHash(input []byte) [sha256.Size]byte {
	e := []byte{NodePrefix}
	e = append(e, input...)
	return sha256.Sum256(e)
}

// buildTree build a new merkle hash tree
func (m *MerkleHashTree) buildTree(entries [][sha256.Size]byte, level int) [sha256.Size]byte {
	n := uint64(len(entries))
	if n == 0 {
		return sha256.Sum256(nil)
	}

	if n == 1 {
		return entries[0]
	}

	k := largestPowerOf2SmallerThan(n)

	left := m.buildTree(entries[0:k], level-1)
	right := m.buildTree(entries[k:n], level-1)
	final := append(left[:], right[:]...)
	hash := nodeHash(final)
	m.tree[level] = append(m.tree[level], hash)
	return hash
}

// TODO: avoid building the entire tree and build only the part of the tree which needs to changed.
// rebuildTree rebuilds the root hash of an exitsing merkle hash tree
func (m *MerkleHashTree) rebuildTree(entries [][sha256.Size]byte, level int, levelIndexMap map[int]int) [sha256.Size]byte {
	n := uint64(len(entries))
	if n == 0 {
		return sha256.Sum256(nil)
	}

	if n == 1 {
		return entries[0]
	}

	k := largestPowerOf2SmallerThan(n)

	left := m.rebuildTree(entries[0:k], level-1, levelIndexMap)
	right := m.rebuildTree(entries[k:n], level-1, levelIndexMap)
	final := append(left[:], right[:]...)
	hash := nodeHash(final)

	index, _ := levelIndexMap[level]
	if index == len(m.tree[level]) {
		m.tree[level] = append(m.tree[level], hash)
	} else {
		m.tree[level][index] = hash
	}

	levelIndexMap[level] = index + 1
	return hash
}

// Print prints the merkle hash tree
func (m *MerkleHashTree) Print() {
	l := len(m.tree)
	tab := ""
	for i := l - 1; i >= 0; i-- {
		fmt.Print(strings.Repeat("  ", (1<<i)-1))
		tab = strings.Repeat("  ", (1<<(i+1))-1)
		for _, v := range m.tree[i] {
			fmt.Printf("%.2x%s", v, tab)
		}
		fmt.Println()
	}
}

// Append adds new leaf nodes to existing merkle hash tree and returns the new merkle root
func (m *MerkleHashTree) Append(d ...[]byte) [sha256.Size]byte {
	for _, e := range d {
		m.tree[0] = append(m.tree[0], leafHash(e))
	}

	l := levels(len(m.tree[0]))
	start := len(m.tree)
	for i := start; i < l; i++ {
		m.tree = append(m.tree, make([][sha256.Size]byte, 0))
	}

	return m.rebuildTree(m.tree[0], l-1, make(map[int]int))
}

// MerkleRoot return root hash or merkle root of a merkle hash tree
func (m *MerkleHashTree) MerkleRoot() [sha256.Size]byte {
	return m.tree[len(m.tree)-1][0]
}

// InclusionProof returns inclusion proof for a merkle tree hash node
func (mth *MerkleHashTree) InclusionProof(e []byte) [][sha256.Size]byte {
	hash := leafHash(e)
	m := IndexOf(mth.tree[0], hash)
	if m < 0 {
		return make([][sha256.Size]byte, 0)
	}

	return mth.AduitPath(m, 0, len(mth.tree[0])-1)
}

func (mth *MerkleHashTree) mthOfRange(start, end int) [sha256.Size]byte {
	if start == end {
		return mth.tree[0][start]
	}

	levels := levels(end - start + 1)
	maxSize := int(math.Pow(2, float64(levels-1)))
	return mth.tree[levels-1][start/maxSize]
}

// AduitPath returns audit path of a merkle hash tree
func (mth *MerkleHashTree) AduitPath(m int, start, end int) [][sha256.Size]byte {
	n := end - start + 1
	path := make([][sha256.Size]byte, 0)

	if n == 0 || start > end {
		return path
	}

	if m < start || m > end {
		return path
	}

	if m == start && n == 1 {
		return path
	}

	k := int(largestPowerOf2SmallerThan(uint64(n)))
	k = start + k
	if m < k {
		path = append(path, mth.AduitPath(m, start, k-1)...)
		path = append(path, mth.mthOfRange(k, end))
	} else {
		path = append(path, mth.AduitPath(m, k, end)...)
		path = append(path, mth.mthOfRange(start, k-1))
	}

	return path
}

// IndexOf returns index of a byte in list of bytes
func IndexOf(entries [][sha256.Size]byte, e [sha256.Size]byte) int {
	for i, b := range entries {
		if bytes.Compare(b[:], e[:]) == 0 {
			return i
		}
	}

	return -1
}

func printPath(path [][sha256.Size]byte) {
	for _, p := range path {
		fmt.Printf("%.2x-->", p)
	}
	fmt.Println()
}

// ConsitencyProof returns the Merkle Consitency Proof for a Merkle Tree
// Hash of first n leaves and previously advertised hash of the first m levaes, m <= n.
func (mth *MerkleHashTree) ConsitencyProof(m, n uint64) [][sha256.Size]byte {
	l := uint64(len(mth.tree[0]))

	if m < 0 || m > n || m > l || n > l {
		return nil
	}
	return mth.subProof(m, 0, int(n-1), true)
}

func (mth *MerkleHashTree) subProof(m uint64, start, end int, isKnown bool) [][sha256.Size]byte {
	path := make([][sha256.Size]byte, 0)
	n := uint64(end - start + 1)

	if m == n && isKnown {
		return path
	}

	if m == n && !isKnown {
		path = append(path, mth.mthOfRange(start, end))
		return path
	}

	if m < n {
		k := largestPowerOf2SmallerThan(n)
		if m <= k {
			path = append(path, mth.subProof(m, start, start+int(k-1), isKnown)...)
			path = append(path, mth.mthOfRange(start+int(k), end))
		} else {
			path = append(path, mth.subProof(m-k, start+int(k), end, false)...)
			path = append(path, mth.mthOfRange(start, start+int(k-1)))
		}
	}
	return path
}
