package merkletree

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_LargestPowerOf2SmallerThan(t *testing.T) {
	tests := []struct {
		name   string
		input  uint64
		output uint64
	}{
		{
			name:   "testcase 1",
			input:  uint64(0),
			output: uint64(0),
		},
		{
			name:   "testcase 2",
			input:  uint64(1),
			output: uint64(0),
		},
		{
			name:   "testcase 3",
			input:  uint64(2),
			output: uint64(1),
		},
		{
			name:   "testcase 4",
			input:  uint64(3),
			output: uint64(2),
		},
		{
			name:   "testcase 5",
			input:  uint64(4),
			output: uint64(2),
		},
		{
			name:   "testcase 6",
			input:  uint64(7),
			output: uint64(4),
		},
		{
			name:   "testcase 7",
			input:  uint64(16),
			output: uint64(8),
		},
	}

	for _, test := range tests {
		got := largestPowerOf2SmallerThan(test.input)
		if test.output != got {
			t.Errorf("%s failed. expected: %d, got: %d", test.name, test.output, got)
		}

	}
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

func makeEntries(limit int) (D [][]byte) {
	for i := 0; i < limit; i++ {
		v := "d" + strconv.FormatInt(int64(i), 10)
		D = append(D, []byte(v))
	}
	return
}

func TestPath(t *testing.T) {
	D := makeEntries(7)
	// The audit path for d0 is [b, h, l].
	path := Path(0, D)
	assert.Len(t, path, 3)
	// The audit path for d3 is [c, g, l].
	path = Path(3, D)
	assert.Len(t, path, 3)
	// The audit path for d4 is [f, j, k].
	path = Path(4, D)
	assert.Len(t, path, 3)
	// The audit path for d6 is [i, k].
	path = Path(6, D)
	assert.Len(t, path, 2)
}

/*

The same tree, built incrementally in four steps:

       hash0          hash1=k
       / \              /  \
      /   \            /    \
     /     \          /      \
     g      c         g       h
    / \     |        / \     / \
    a b     d2       a b     c d
    | |              | |     | |
   d0 d1            d0 d1   d2 d3

             hash2                    hash
             /  \                    /    \
            /    \                  /      \
           /      \                /        \
          /        \              /          \
         /          \            /            \
        k            i          k              l
       / \          / \        / \            / \
      /   \         e f       /   \          /   \
     /     \        | |      /     \        /     \
    g       h      d4 d5    g       h      i      j
   / \     / \             / \     / \    / \     |
   a b     c d             a b     c d    e f     d6
   | |     | |             | |     | |    | |
   d0 d1   d2 d3           d0 d1   d2 d3  d4 d5

*/

func TestProof(t *testing.T) {
	D := makeEntries(7)

	// The consistency proof between hash0 and hash is PROOF(3, D[7]) = [c,
	// d, g, l].  c, g are used to verify hash0, and d, l are additionally
	// used to show hash is consistent with hash0.
	path := Proof(3, D)
	assert.Len(t, path, 4)

	// assert.ElementsMatch(t, path, [][sha256.Size]byte{leafHash(D[2]), leafHash(D[3]), nodeHash([]byte{'g'}), nodeHash([]byte{'l'})})

	// The consistency proof between hash1 and hash is PROOF(4, D[7]) = [l].
	// hash can be verified using hash1=k and l.
	path = Proof(4, D)
	assert.Len(t, path, 1)

	// The consistency proof between hash2 and hash is PROOF(6, D[7]) = [i,
	// j, k].  k, i are used to verify hash2, and j is additionally used to
	// show hash is consistent with hash2.
	path = Proof(6, D)
	assert.Len(t, path, 3)
}

func makeRangeEntries(start, end int) (D [][]byte) {
	for i := start; i < end; i++ {
		v := "d" + strconv.FormatInt(int64(i), 10)
		D = append(D, []byte(v))
	}
	return
}
