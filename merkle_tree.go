package merkletree

import "crypto/sha256"

// Prefixes for leaves and nodes
const (
	LeafPrefix = byte(0)
	NodePrefix = byte(1)
)

func largestPowerOf2SmallerThan(n uint64) uint64 {
	if n < 2 {
		return uint64(0)
	}

	cur := uint64(1)
	prev := uint64(1)
	for i := 0; i < 64; i++ {
		cur = cur * 2
		if cur > n-1 {
			return prev
		}
		prev = cur
	}

	return uint64(0)
}

// MTH returns Merkle Hash Tree. The input to the Merkle Tree Hash is a list of data entries;
// The output is a single 32-byte Merkle Tree Hash.
func MTH(D [][]byte) [sha256.Size]byte {
	n := uint64(len(D))

	// The hash of an empty list is the hash of an empty string: MTH({}) = SHA-256().
	if n == 0 {
		return sha256.Sum256(nil)
	}

	// The hash of a list with one entry (also known as a leaf hash) is:  MTH({d(0)}) = SHA-256(0x00 || d(0)).
	if n == 1 {
		e := []byte{LeafPrefix}
		e = append(e, D[0]...)
		return sha256.Sum256(e)
	}

	// For n > 1, let k be the largest power of two smaller than n (i.e.,k < n <= 2k).
	// The Merkle Tree Hash of an n-element list D[n] is then
	// defined recursively as MTH(D[n]) = SHA - 256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))

	k := largestPowerOf2SmallerThan(n)

	e := []byte{NodePrefix}
	x := MTH(D[0:k])
	e = append(e, x[:]...)
	x = MTH(D[k:n])
	e = append(e, x[:]...)
	return sha256.Sum256(e)
}

// Path returns a merkle auidt path. A Merkle audit path for a leaf in a Merkle Hash Tree is the shortest
// list of additional nodes in the Merkle Tree required to compute the Merkle Tree Hash for that tree.
// The audit path consists of the list of missing nodes required to compute the nodes leading from a leaf to the root of the tree.
func Path(m uint64, D [][]byte) [][sha256.Size]byte {
	n := uint64(len(D))
	path := make([][sha256.Size]byte, 0)

	if m < 0 || m > n {
		return path
	}

	// The path for the single leaf in a tree with a one-element input list D[1] = {d(0)} is empty: PATH(0, {d(0)}) = {}
	if m == 0 && n == 1 {
		return path
	}

	k := largestPowerOf2SmallerThan(n)

	if m < k {
		// for m < k; PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])
		path = append(path, Path(m, D[0:k])...)
		path = append(path, MTH(D[k:n]))
	} else {
		// for m >= k, PATH(m, D[n]) = PATH(m - k, D[k:n]) : MTH(D[0:k])
		path = append(path, Path(m-k, D[k:n])...)
		path = append(path, MTH(D[0:k]))
	}

	return path
}

func subProof(m uint64, D [][]byte, isKnown bool) (path [][sha256.Size]byte) {
	path = make([][sha256.Size]byte, 0)
	n := uint64(len(D))

	// The subproof for m = n is empty if m is the value for which PROOF was
	// originally requested (meaning that the subtree Merkle Tree Hash MTH(D[0:m]) is known): SUBPROOF(m, D[m], true) = {}
	if m == n && isKnown {
		return
	}

	// The subproof for m = n is the Merkle Tree Hash committing inputs D[0:m]; otherwise: SUBPROOF(m, D[m], false) = {MTH(D[m])}
	if m == n && !isKnown {
		path = append(path, MTH(D))
		return
	}

	// For m < n, let k be the largest power of two smaller than n.  The subproof is then defined recursively.
	if m < n {
		k := largestPowerOf2SmallerThan(n)

		if m <= k {
			// If m <= k, the right subtree entries D[k:n] only exist in the current
			// tree.  We prove that the left subtree entries D[0:k] are consistent
			// and add a commitment to D[k:n]: SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])
			path = append(path, subProof(m, D[0:k], isKnown)...)
			path = append(path, MTH(D[k:n]))
		} else {
			// If m > k, the left subtree entries D[0:k] are identical in both
			// trees.  We prove that the right subtree entries D[k:n] are consistent
			// and add a commitment to D[0:k]: SUBPROOF(m, D[n], b) = SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k])
			path = append(path, subProof(m-k, D[k:n], false)...)
			path = append(path, MTH(D[0:k]))
		}
	}

	return
}

// Proof returns the Merkle Consitency Proof for a Merkle Tree Hash MTH(D[n]) and
// a previously advertised hash MTH(D[0:m]) of the first m leaves, m <= n.
// It returns the list of nodes in the Merkle Tree required to verify that the first m inputs D[0:m] are equal in both trees.
// Merkle consistency proofs prove the append-only property of the tree.
func Proof(m uint64, D [][]byte) [][sha256.Size]byte {
	n := uint64(len(D))

	if m < 0 || m > n {
		return nil
	}

	// Given an ordered list of n inputs to the tree, D[n] = {d(0), ...,d(n-1)},
	// the Merkle consistency proof PROOF(m, D[n]) for a previous Merkle Tree Hash MTH(D[0:m]),
	// 0 < m < n, is defined as: PROOF(m, D[n]) = SUBPROOF(m, D[n], true)

	return subProof(m, D, true)
}
