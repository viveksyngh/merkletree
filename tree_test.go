package merkletree

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMerkleHashTree(t *testing.T) {
	D := makeEntries(7)
	tree := New(D)
	// tree.Print()
	prevMerkleTree := tree.MerkleRoot()
	assert.Equal(t, 4, len(tree.tree))
	// fmt.Printf("Merkle Root: %x\n", tree.MerkleRoot())

	newEntries := makeRangeEntries(7, 8)
	tree.Append(newEntries...)
	// tree.Print()
	assert.Equal(t, 4, len(tree.tree))
	assert.NotEqual(t, prevMerkleTree, tree.MerkleRoot())
	prevMerkleTree = tree.MerkleRoot()
	// fmt.Printf("Merkle Root: %x\n", tree.MerkleRoot())

	newEntries = makeRangeEntries(8, 9)
	tree.Append(newEntries...)
	// tree.Print()
	assert.Equal(t, 5, len(tree.tree))
	assert.NotEqual(t, prevMerkleTree, tree.MerkleRoot())
	prevMerkleTree = tree.MerkleRoot()
	// fmt.Printf("Merkle Root: %x\n", tree.MerkleRoot())

	newEntries = makeRangeEntries(9, 16)
	tree.Append(newEntries...)
	// tree.Print()
	assert.Equal(t, 5, len(tree.tree))
	assert.NotEqual(t, prevMerkleTree, tree.MerkleRoot())
	// fmt.Printf("Merkle Root: %x\n", tree.MerkleRoot())

	prevMerkleTree = tree.MerkleRoot()
	newMerkleTree := tree.Append()
	assert.Equal(t, prevMerkleTree, newMerkleTree)
}

/*
 The binary Merkle Tree with 7 leaves:

               hash
              /    \
             /      \
            /        \
           /          \
          /            \
         k              l
        / \            / \
       /   \          /   \
      /     \        /     \
     g       h      i      j
    / \     / \    / \     |
    a b     c d    e f     d6
    | |     | |    | |
   d0 d1   d2 d3  d4 d5
*/

func TestInclusionProof(t *testing.T) {
	D := makeEntries(7)
	tree := New(D)
	// tree.Print()

	path := tree.InclusionProof(D[0])
	// printPath(path)
	assert.Len(t, path, 3)

	path = tree.InclusionProof(D[6])
	// printPath(path)
	assert.Len(t, path, 2)

	// The audit path for d3 is [c, g, l].
	path = tree.InclusionProof(D[3])
	// printPath(path)
	assert.Len(t, path, 3)

	// The audit path for d4 is [f, j, k].
	path = tree.InclusionProof(D[4])
	// printPath(path)
	assert.Len(t, path, 3)

}

func TestMTHOfRange(t *testing.T) {
	D := makeEntries(7)
	tree := New(D)
	// tree.Print()

	assert.Equal(t, tree.tree[3][0], tree.mthOfRange(0, 6))
	assert.Equal(t, tree.tree[1][0], tree.mthOfRange(0, 1))
	assert.Equal(t, tree.tree[2][1], tree.mthOfRange(4, 6))
	assert.Equal(t, tree.tree[2][0], tree.mthOfRange(0, 3))

	D = makeEntries(8)
	tree = New(D)
	assert.Equal(t, tree.tree[3][0], tree.mthOfRange(0, 7))
	assert.Equal(t, tree.tree[1][0], tree.mthOfRange(0, 1))
	assert.Equal(t, tree.tree[2][1], tree.mthOfRange(4, 7))
	assert.Equal(t, tree.tree[2][0], tree.mthOfRange(0, 3))
	assert.Equal(t, tree.tree[0][1], tree.mthOfRange(1, 1))

	D = makeEntries(2)
	tree = New(D)
	assert.Equal(t, tree.tree[1][0], tree.mthOfRange(0, 1))

}

func TestConsistencyProof(t *testing.T) {
	D := makeEntries(7)
	tree := New(D)

	// The consistency proof between hash0 and hash is PROOF(3, D[7]) = [c,
	// d, g, l].  c, g are used to verify hash0, and d, l are additionally
	// used to show hash is consistent with hash0.
	path := tree.ConsitencyProof(3, 7)
	assert.Len(t, path, 4)

	// assert.ElementsMatch(t, path, [][sha256.Size]byte{leafHash(D[2]), leafHash(D[3]), nodeHash([]byte{'g'}), nodeHash([]byte{'l'})})

	// The consistency proof between hash1 and hash is PROOF(4, D[7]) = [l].
	// hash can be verified using hash1=k and l.
	path = tree.ConsitencyProof(4, 7)
	assert.Len(t, path, 1)

	// The consistency proof between hash2 and hash is PROOF(6, D[7]) = [i,
	// j, k].  k, i are used to verify hash2, and j is additionally used to
	// show hash is consistent with hash2.
	path = tree.ConsitencyProof(6, 7)
	assert.Len(t, path, 3)
}
