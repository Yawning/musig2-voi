// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: SSPL-1.0

package musig2

import (
	"bytes"
	csrand "crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math"

	"gitlab.com/yawning/secp256k1-voi"
	"gitlab.com/yawning/secp256k1-voi/secec"
)

const (
	// PublicNonceSize is the size of a byte-encoded (Aggregated)PublicNonce
	// in bytes.
	PublicNonceSize = 66 // secp256k1.CompressedPointSize * 2
	// SecretNonceSize is the size of a byte-encoded SecretNonce in bytes.
	SecretNonceSize = 97

	nonceEntropySize = 32
	maxNonces        = math.MaxUint32

	tagNonceAux         = "MuSig/aux"
	tagNonce            = "MuSig/nonce"
	tagNonceCoefficient = "MuSig/noncecoef"
)

var (
	errInvalidPublicNonce    = errors.New("musig2: invalid public nonce")
	errInvalidSecretNonce    = errors.New("musig2: invalid secret nonce")
	errEntropySource         = errors.New("musig2: entropy source failure")
	errInvalidExtraInput     = errors.New("musig2: invalid exra input")
	errKIsZero               = errors.New("musig2: k1 or k2 is zero")
	errInvalidNumberOfNonces = errors.New("musig2: invalid number of nonces")
)

// PublicNonce is an un-aggregated (individual) public nonce.
type PublicNonce struct {
	r1, r2 *secp256k1.Point
	b      []byte
}

// Bytes returns the byte-encoding of the PublicNonce.
func (n *PublicNonce) Bytes() []byte {
	if len(n.b) == 0 {
		panic(errInvalidPublicNonce)
	}
	return bytes.Clone(n.b)
}

// NewPublicNonce deserializes a PublicNonce from the byte-encoded form.
func NewPublicNonce(b []byte) (*PublicNonce, error) {
	n, err := NewAggregatedPublicNonce(b)
	if err != nil {
		return nil, err
	}

	if !n.isValidPublic() {
		return nil, errInvalidPublicNonce
	}

	return (*PublicNonce)(n), nil
}

// AggregatedPublicNnce is an aggregated (group) public nonce.
type AggregatedPublicNonce PublicNonce

// Bytes returns the byte-encoding of the AggregatedPublicNonce.
func (n *AggregatedPublicNonce) Bytes() []byte {
	if len(n.b) == 0 {
		panic(errInvalidPublicNonce)
	}
	return bytes.Clone(n.b)
}

func (n *AggregatedPublicNonce) isValidPublic() bool {
	return n.r1.IsIdentity() == 0 && n.r2.IsIdentity() == 0
}

// NewAggregatedPublicNonce deserializes an AggregatedPublicNonce from the
// byte-encoded form.
func NewAggregatedPublicNonce(b []byte) (*AggregatedPublicNonce, error) {
	if len(b) != PublicNonceSize {
		return nil, errInvalidPublicNonce
	}

	// Either point in an aggregated nonce can be the point at
	// infinity, encoded as 33 0s (`cbytes_ext`, `cpoint_ext`).
	r1, r2 := secp256k1.NewIdentityPoint(), secp256k1.NewIdentityPoint()
	b1, b2 := b[:secp256k1.CompressedPointSize], b[secp256k1.CompressedPointSize:]
	if !bytes.Equal(b1, cIdentityBytes) {
		if _, err := r1.SetCompressedBytes(b1); err != nil {
			return nil, errors.Join(errInvalidPublicNonce, err)
		}
	}
	if !bytes.Equal(b2, cIdentityBytes) {
		if _, err := r2.SetCompressedBytes(b2); err != nil {
			return nil, errors.Join(errInvalidPublicNonce, err)
		}
	}

	return &AggregatedPublicNonce{
		r1: r1,
		r2: r2,
		b:  bytes.Clone(b),
	}, nil
}

// SecretNonce is a individual secret nonce.
//
// WARNING: This value MUST NEVER be reused or exposed otherwise the
// signing key will be trivially compromised from partial signature(s).
type SecretNonce struct {
	k1, k2 *secp256k1.Scalar
	pk     *secp256k1.Point

	publicNonce *PublicNonce
}

// Bytes returns the byte-encoding of the SecretNonce.
func (n *SecretNonce) Bytes() []byte {
	b := make([]byte, 0, SecretNonceSize)
	b = append(b, n.k1.Bytes()...)
	b = append(b, n.k2.Bytes()...)
	b = append(b, n.pk.CompressedBytes()...)
	return b
}

// PublicNonce returns the SecretNonce's corresponding PublicNonce.
func (n *SecretNonce) PublicNonce() *PublicNonce {
	return n.publicNonce
}

// IsFor returns true iff the SecretNonce is associated with the provided
// PublicKey.
func (n *SecretNonce) IsFor(pk *secec.PublicKey) bool {
	return pk.Point().Equal(n.pk) == 1
}

// IsValid returns true iff the SecretNonce appears to be valid.
func (n *SecretNonce) IsValid() bool {
	notOk := n.pk.IsIdentity() | n.k1.IsZero() | n.k2.IsZero()
	return notOk == 0
}

// Invalidate clears the internal values of a SecretNonce such that it
// can no longer be used via Sign.  This is intended as operator error
// mitigation, rather than secure erasure.
func (n *SecretNonce) Invalidate() {
	n.k1.Zero()
	n.k2.Zero()
	n.pk.Identity()
}

func (n *SecretNonce) genPublicNonce() *PublicNonce {
	// Let R_1 = k1 * G, R_2 = k2 * G
	r1 := secp256k1.NewIdentityPoint().ScalarBaseMult(n.k1)
	r2 := secp256k1.NewIdentityPoint().ScalarBaseMult(n.k2)

	// Let pubnonce = cbytes(R_1) || cbytes(R_2)
	b := make([]byte, 0, PublicNonceSize)
	b = append(b, r1.CompressedBytes()...)
	b = append(b, r2.CompressedBytes()...)
	return &PublicNonce{
		r1: r1,
		r2: r2,
		b:  b,
	}
}

// NewSecretNonce deserializes a SecretNonce from the byte-encoded form.
func NewSecretNonce(b []byte) (*SecretNonce, error) {
	if len(b) != SecretNonceSize {
		return nil, errInvalidSecretNonce
	}

	k1Bytes := (*[secp256k1.ScalarSize]byte)(b[:32])
	k2Bytes := (*[secp256k1.ScalarSize]byte)(b[32:64])
	pkBytes := b[64:]

	k1, err := secp256k1.NewScalarFromCanonicalBytes(k1Bytes)
	if err != nil {
		return nil, errors.Join(errInvalidSecretNonce, err)
	}
	k2, err := secp256k1.NewScalarFromCanonicalBytes(k2Bytes)
	if err != nil {
		return nil, errors.Join(errInvalidSecretNonce, err)
	}
	if k1.IsZero() != 0 || k2.IsZero() != 0 {
		return nil, errKIsZero
	}
	pk, err := secp256k1.NewIdentityPoint().SetCompressedBytes(pkBytes)
	if err != nil {
		return nil, errors.Join(errInvalidSecretNonce, err)
	}

	secnonce := &SecretNonce{
		k1: k1,
		k2: k2,
		pk: pk,
	}
	secnonce.publicNonce = secnonce.genPublicNonce()

	return secnonce, nil
}

// GenerateNonce generates a new SecretNonce/PublicNonce pair for a given
// individual PublicKey.  All other parameters are optional, but strongly
// recommended, to reduce the probability of nonce-reuse.
//
// Note that there is a difference in output generated between `msg = nil`
// and `msg = []byte{}`, as the algorithm treats omitting msg entirely
// differently from msg that is the empty byte string.
func GenerateNonce(k *secec.PublicKey, sk *secec.PrivateKey, aggPk *AggregatedPublicKey, msg, extraIn []byte) (*SecretNonce, *PublicNonce, error) {
	// Let rand' be a 32-byte array freshly drawn uniformly at random
	var randP [nonceEntropySize]byte
	if _, err := csrand.Read(randP[:]); err != nil {
		return nil, nil, errors.Join(errEntropySource, err)
	}

	var aggPkBytes []byte
	if aggPk != nil {
		aggPkBytes = aggPk.xBytes()
	}

	return nonceGen(k, sk, aggPkBytes, msg, extraIn, randP[:])
}

func nonceGen(k *secec.PublicKey, sk *secec.PrivateKey, aggpk, m, extraIn, randP []byte) (*SecretNonce, *PublicNonce, error) {
	var rand []byte
	// If the optional argument sk is present:
	if sk != nil {
		// This is possibly "harmless", but it is a sign that
		// the caller is doing something horrifically wrong.
		if !sk.PublicKey().Equal(k) {
			panic("musig2: public/private key mismatch") // Yes, a panic.
		}

		// Let rand be the byte-wise xor of sk and hashMuSig/aux(rand')
		rand = sk.Bytes()
		subtle.XORBytes(rand, rand, taggedHash(tagNonceAux, randP))
	} else {
		// Else: Let rand = rand'
		rand = randP
	}

	// If the optional argument aggpk is not present:
	// Let aggpk = empty_bytestring

	// If the optional argument extra_in is not present:
	// Let extra_in = empty_bytestring

	// Let ki = int(
	//   hashMuSig/nonce(
	//     rand ||
	//     bytes(1, len(pk)) || pk ||
	//     bytes(1, len(aggpk)) || aggpk ||
	//     m_prefixed ||
	//     bytes(4, len(extra_in)) || extra_in ||
	//     bytes(1, i - 1)
	//   )
	// ) mod n for i = 1,2
	//
	// Note/yawning: Just use TupleHash, Jesus fucking Christ.

	kBytes := k.CompressedBytes() //nolint:revive

	h := newTaggedHash(tagNonce)
	_, _ = h.Write(rand)                      // rand
	_, _ = h.Write([]byte{byte(len(kBytes))}) // bytes(1, len(pk))
	_, _ = h.Write(kBytes)                    // pk
	_, _ = h.Write([]byte{byte(len(aggpk))})  // bytes(1, len(aggpk))
	_, _ = h.Write(aggpk)                     // aggpk

	// If the optional argument m is not present:
	if m == nil { // NOT `m == len(0)` to distinguish `no m` vs `0-length m`.
		// Let m_prefixed = bytes(1, 0)
		_, _ = h.Write([]byte{0}) // m_prefixed bytes(1, 0)
	} else {
		// Else: Let m_prefixed = bytes(1, 1) || bytes(8, len(m)) || m
		_, _ = h.Write([]byte{1})                             // bytes(1, 1)
		_ = binary.Write(h, binary.BigEndian, uint64(len(m))) // bytes(8, len(m))
		_, _ = h.Write(m)                                     // m
	}

	l := len(extraIn)
	if uint64(l) > math.MaxUint32 {
		return nil, nil, errInvalidExtraInput
	}
	_ = binary.Write(h, binary.BigEndian, uint32(l)) // bytes(4, len(extra_in))
	_, _ = h.Write(extraIn)                          // extra_in

	h2 := cloneHash(h)
	_, _ = h.Write([]byte{0})  // bytes(1, i - 1), i = 1
	_, _ = h2.Write([]byte{1}) // bytes(1, i - 1), i = 2

	k1, _ := secp256k1.NewScalarFromBytes((*[secp256k1.ScalarSize]byte)(h.Sum(nil)))
	k2, _ := secp256k1.NewScalarFromBytes((*[secp256k1.ScalarSize]byte)(h2.Sum(nil)))

	// Fail if k1 = 0 or k2 = 0
	if k1.IsZero() != 0 || k2.IsZero() != 0 {
		return nil, nil, errKIsZero
	}

	// Let secnonce = bytes(32, k1) || bytes(32, k2) || pk
	secnonce := &SecretNonce{
		k1: k1,
		k2: k2,
		pk: k.Point(),
	}
	secnonce.publicNonce = secnonce.genPublicNonce()

	return secnonce, secnonce.PublicNonce(), nil
}

// PublicNonceAggregator accumulates PublicNonces, before doing the final aggregation
// and generating an AggregatedPublicNonce.
type PublicNonceAggregator struct {
	r1, r2 *secp256k1.Point
	u      uint64
}

// Add adds a PublicNonce to the nonce aggregator.
func (agg *PublicNonceAggregator) Add(nonce *PublicNonce) error {
	if agg.u+1 > maxNonces {
		return errInvalidNumberOfNonces
	}

	// Let Ri,j = cpoint(pubnonce_i[(j-1)*33:j*33]); fail if
	// that fails and blame signer i for invalid pubnonce.
	//
	// Note/yawning: Like with KeyAgg, since we use sensible
	// data-types, nonce is guaranteed to be valid.

	if agg.r1 == nil {
		if agg.r2 != nil || agg.u != 0 {
			panic("musig2: BUG: PublicNonceAggregator state corruption")
		}
		agg.r1 = secp256k1.NewPointFrom(nonce.r1)
		agg.r2 = secp256k1.NewPointFrom(nonce.r2)
	} else {
		agg.r1.Add(agg.r1, nonce.r1)
		agg.r2.Add(agg.r2, nonce.r2)
	}
	agg.u++

	return nil
}

// Aggregate produces an AggregatedPublicNonce.  This operation does not affect
// the state of the PublicNonceAggregator.
func (agg *PublicNonceAggregator) Aggregate() (*AggregatedPublicNonce, error) {
	if agg.u > maxNonces || agg.u == 0 {
		return nil, errInvalidNumberOfNonces
	}

	// Let Rj = R1,j + R2,j + ... + Ru,j
	//
	// Note/yawning: Done incrementally as part of add.

	r1, r2 := secp256k1.NewPointFrom(agg.r1), secp256k1.NewPointFrom(agg.r2)

	// Return aggnonce = cbytes_ext(R1) || cbytes_ext(R2)
	b := make([]byte, 0, PublicNonceSize)
	if r1.IsIdentity() != 0 {
		b = append(b, cIdentityBytes...)
	} else {
		b = append(b, r1.CompressedBytes()...)
	}
	if r2.IsIdentity() != 0 {
		b = append(b, cIdentityBytes...)
	} else {
		b = append(b, r2.CompressedBytes()...)
	}

	return &AggregatedPublicNonce{
		r1: r1,
		r2: r2,
		b:  b,
	}, nil
}

// NewPublicNonceAggregator creates an empty PublicNonceAggregator.
func NewPublicNonceAggregator() *PublicNonceAggregator {
	return new(PublicNonceAggregator)
}
