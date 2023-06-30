// Package musig2 implements the MuSig2 multi-signature algorithm as
// specified in BIP-0327.
package musig2

import (
	"crypto/sha256"
	"encoding"
	"hash"

	"gitlab.com/yawning/secp256k1-voi"
)

// Dumping ground for various helpers.

func newTaggedHash(tag string) hash.Hash {
	hashedTag := sha256.Sum256([]byte(tag))

	h := sha256.New()
	_, _ = h.Write(hashedTag[:])
	_, _ = h.Write(hashedTag[:])
	return h
}

func taggedHash(tag string, vals ...[]byte) []byte {
	h := newTaggedHash(tag)
	for _, v := range vals {
		_, _ = h.Write(v)
	}
	return h.Sum(nil)
}

func cloneHash(h hash.Hash) hash.Hash {
	// This is so stupid, but it appears to be the only way to copy
	// hash state, and it's and improvement to do this, if only for
	// readability reasons.

	m := h.(encoding.BinaryMarshaler)
	st, err := m.MarshalBinary()
	if err != nil {
		panic("musig2: failed to serialize hash: " + err.Error())
	}

	nh := sha256.New()
	um := nh.(encoding.BinaryUnmarshaler)
	if err = um.UnmarshalBinary(st); err != nil {
		panic("musig2: failed to deserialize hash: " + err.Error())
	}

	return nh
}

// TODO: At some point, these could be upstreamed into the Scalar
// implementation.

func mulScalars(vec ...*secp256k1.Scalar) *secp256k1.Scalar {
	product := secp256k1.NewScalar().One()
	for _, v := range vec {
		product.Multiply(product, v)
	}
	return product
}

func sumScalars(vec ...*secp256k1.Scalar) *secp256k1.Scalar {
	sum := secp256k1.NewScalar()
	for _, v := range vec {
		sum.Add(sum, v)
	}
	return sum
}
