package musig2

import (
	"bytes"
	csrand "crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math"

	"gitlab.com/yawning/secp256k1-voi"
)

const (
	PublicNonceSize = 66 // secp256k1.CompressedPointSize * 2

	nonceEntropySize = 32

	tagNonceAux         = "MuSig/aux"
	tagNonce            = "MuSig/nonce"
	tagNonceCoefficient = "MuSig/noncecoef"
)

var (
	errInvalidPublicNonce    = errors.New("musig2: invalid public nonce")
	errEntropySource         = errors.New("musig2: entropy source failure")
	errKeyMismatch           = errors.New("musig2: public/private key mismatch")
	errInvalidExtraInput     = errors.New("musig2: invalid exra input")
	errKIsZero               = errors.New("musig2: k1 or k2 is zero")
	errInvalidNumberOfNonces = errors.New("musig2: invalid number of nonces")

	cIdentityBytes = make([]byte, secp256k1.CompressedPointSize)
)

type PublicNonce struct {
	r1, r2 *secp256k1.Point
	b      []byte
}

func (n *PublicNonce) isValidPublic() bool {
	return n.r1.IsIdentity() == 0 && n.r2.IsIdentity() == 0
}

func (n *PublicNonce) Bytes() []byte {
	if len(n.b) == 0 {
		panic(errInvalidPublicNonce)
	}
	return n.b
}

func NewPublicNonce(b []byte) (*PublicNonce, error) {
	n, err := NewAggregatedPublicNonce(b)
	if err != nil {
		return nil, err
	}

	if !n.isValidPublic() {
		return nil, errInvalidPublicNonce
	}

	return n, nil
}

func NewAggregatedPublicNonce(b []byte) (*PublicNonce, error) {
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

	return &PublicNonce{
		r1: r1,
		r2: r2,
		b:  bytes.Clone(b),
	}, nil
}

type SecretNonce struct {
	k1, k2 *secp256k1.Scalar
	pk     *secp256k1.Point

	pn *PublicNonce
}

// XXX: Figure out how to handle SecretNonce s11n vs consumption.

// XXX/yawning: aggpk -> type
func (k *PublicKey) NonceGen(sk *PrivateKey, aggpk, m, extraIn []byte) (*SecretNonce, *PublicNonce, error) {
	// Let rand' be a 32-byte array freshly drawn uniformly at random
	var randP [nonceEntropySize]byte
	if _, err := csrand.Read(randP[:]); err != nil {
		return nil, nil, errors.Join(errEntropySource, err)
	}
	return k.nonceGen(sk, aggpk, m, extraIn, randP[:])
}

func (k *PublicKey) nonceGen(sk *PrivateKey, aggpk, m, extraIn, randP []byte) (*SecretNonce, *PublicNonce, error) {
	var rand []byte
	// If the optional argument sk is present:
	if sk != nil {
		// This is possibly "harmless", but it is a sign that
		// the caller is doing something horrifically wrong.
		if !sk.pk.Equal(k) {
			panic(errKeyMismatch) // Yes, a panic.
		}

		// Let rand be the byte-wise xor of sk and hashMuSig/aux(rand')
		rand = sk.dPrime.Bytes()
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

	h := newTaggedHash(tagNonce)
	_, _ = h.Write(rand)                        // rand
	_, _ = h.Write([]byte{byte(len(k.pBytes))}) // bytes(1, len(pk))
	_, _ = h.Write(k.pBytes)                    // pk
	_, _ = h.Write([]byte{byte(len(aggpk))})    // bytes(1, len(aggpk))
	_, _ = h.Write(aggpk)                       // aggpk

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

	// Let R_1 = k1 * G, R_2 = k2 * G
	R_1 := secp256k1.NewIdentityPoint().ScalarBaseMult(k1)
	R_2 := secp256k1.NewIdentityPoint().ScalarBaseMult(k2)

	// Let pubnonce = cbytes(R_1) || cbytes(R_2)
	b := make([]byte, 0, PublicNonceSize)
	b = append(b, R_1.CompressedBytes()...)
	b = append(b, R_2.CompressedBytes()...)
	pubnonce := &PublicNonce{
		r1: R_1,
		r2: R_2,
		b:  b,
	}

	// Let secnonce = bytes(32, k1) || bytes(32, k2) || pk
	secnonce := &SecretNonce{
		k1: k1,
		k2: k2,
		pk: secp256k1.NewPointFrom(k.p),
		pn: pubnonce, // XXX/yawning: Clone this or something....
	}

	return secnonce, pubnonce, nil
}

func NonceAgg(nonces []*PublicNonce) (*PublicNonce, error) {
	u := len(nonces)
	if uint64(u) > math.MaxUint32 {
		return nil, errInvalidNumberOfNonces
	}

	R_1, R_2 := secp256k1.NewIdentityPoint(), secp256k1.NewIdentityPoint()

	// For j = 1 .. 2:
	//   For i = 1 .. u:
	for _, n := range nonces {
		// Let Ri,j = cpoint(pubnonce_i[(j-1)*33:j*33]); fail if
		// that fails and blame signer i for invalid pubnonce.
		//
		// Note/yawning: Like with KeyAgg, since we use sensible
		// data-types, nonces is guaranteed to be a vector of
		// PublicNonces, unless the caller did something stupid.
		if !n.isValidPublic() {
			// In which case, they get a panic.
			panic(errInvalidPublicNonce)
		}

		R_1.Add(R_1, n.r1)
		R_2.Add(R_2, n.r2)
	}

	// Let Rj = R1,j + R2,j + ... + Ru,j
	//
	// Note: Done in the for loop.

	// Return aggnonce = cbytes_ext(R1) || cbytes_ext(R2)
	b := make([]byte, 0, PublicNonceSize)
	if R_1.IsIdentity() != 0 {
		b = append(b, cIdentityBytes...)
	} else {
		b = append(b, R_1.CompressedBytes()...)
	}
	if R_2.IsIdentity() != 0 {
		b = append(b, cIdentityBytes...)
	} else {
		b = append(b, R_2.CompressedBytes()...)
	}

	return &PublicNonce{
		r1: R_1,
		r2: R_2,
		b:  b,
	}, nil
}
