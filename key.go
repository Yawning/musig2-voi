// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: SSPL-1.0

package musig2

import (
	"bytes"
	"errors"
	"math"
	"sort"

	"gitlab.com/yawning/secp256k1-voi"
	"gitlab.com/yawning/secp256k1-voi/secec"
	"gitlab.com/yawning/secp256k1-voi/secec/bitcoin"
)

const (
	// TweakSize is the size of an aggregated public key tweak in bytes.
	TweakSize = 32 // secp256k1.ScalarSize

	maxPublicKeys = math.MaxUint32

	tagKeyAggList        = "KeyAgg list"
	tagKeyAggCoefficient = "KeyAgg coefficient"
)

var (
	scOne    = secp256k1.NewScalar().One()
	scNegOne = secp256k1.NewScalar().Negate(scOne)

	errInvalidNumberOfKeys = errors.New("musig2: invalid number of public keys")
	errInvalidTweak        = errors.New("musig2: invalid tweak")
	errPublicKeyNotInAgg   = errors.New("musig2: public key not part of aggregate key")
	errQIsInfinity         = errors.New("musig2: Q is the point at infinity")
)

func keySort(pks []*secec.PublicKey) []*secec.PublicKey {
	// INVARIANT: 0 < u < maxPublicKeys
	ret := make([]*secec.PublicKey, 0, len(pks))
	ret = append(ret, pks...)

	// Return pk_1..u sorted in lexicographical order.
	sort.SliceStable(
		ret,
		func(i, j int) bool {
			return bytes.Compare(ret[i].CompressedBytes(), ret[j].CompressedBytes()) < 0
		},
	)

	return ret
}

// AggregatedPublicKey is the aggregated and tweaked public key.
type AggregatedPublicKey struct {
	q    *secp256k1.Point // Invariant: Not infinity
	tacc *secp256k1.Scalar
	gacc *secp256k1.Scalar

	pks []*secec.PublicKey
	pk2 []byte // GetSecondKey(pk_1..u)
	l   []byte // HashKeys(pk_1..u)
}

// ApplyTweak applies a tweak to the aggregated public key.
func (aggPk *AggregatedPublicKey) ApplyTweak(tweak []byte, isXOnlyTweak bool) error {
	if len(tweak) != TweakSize {
		return errInvalidTweak
	}

	// Let (Q, gacc, tacc) = keyagg_ctx

	// If is_xonly_t and not has_even_y(Q):
	g := scOne // Else: Let g = 1
	if isXOnlyTweak && aggPk.q.IsYOdd() != 0 {
		// Let g = -1 mod n
		g = scNegOne
	}

	// Let t = int(tweak); fail if t >= n
	t, err := secp256k1.NewScalarFromCanonicalBytes((*[secp256k1.ScalarSize]byte)(tweak))
	if err != nil {
		return errors.Join(errInvalidTweak, err)
	}

	// Let Q' = g * Q + t * G
	qP := secp256k1.NewIdentityPoint().DoubleScalarMultBasepointVartime(t, g, aggPk.q)

	// Fail if is_infinite(Q')
	if qP.IsIdentity() != 0 {
		return errQIsInfinity
	}

	// Let gacc' = g * gacc mod n
	aggPk.gacc.Multiply(g, aggPk.gacc)

	// Let tacc' = t + g * tacc mod n
	aggPk.tacc = secp256k1.NewScalar().Sum(t, secp256k1.NewScalar().Product(g, aggPk.tacc))

	// Return keyagg_ctx' = (Q', gacc', tacc')
	aggPk.q.Set(qP)

	return nil
}

// Schnorr returns the BIP-340 Schnorr public key corresponding to the
// aggregated public key.
func (aggPk *AggregatedPublicKey) Schnorr() *bitcoin.SchnorrPublicKey {
	pk, err := bitcoin.NewSchnorrPublicKey(aggPk.xBytes())
	if err != nil {
		panic(err)
	}
	return pk
}

func (aggPk *AggregatedPublicKey) xBytes() []byte {
	b, err := aggPk.q.XBytes()
	if err != nil {
		panic(err)
	}
	return b
}

func (aggPk *AggregatedPublicKey) getSessionKeyAggCoeff(pk *secec.PublicKey) (*secp256k1.Scalar, error) {
	// Fail if pk not in pk_1..u
	var ok bool
	for _, v := range aggPk.pks {
		if ok = v.Equal(pk); ok {
			break
		}
	}
	if !ok {
		return nil, errPublicKeyNotInAgg
	}

	// Return KeyAggCoeff(pk1..u, pk)
	//
	//   Internal Algorithm KeyAggCoeff(pk_1..u, pk')
	//     Let pk2 = GetSecondKey(pk_1..u):
	//     Return KeyAggCoeffInternal(pk_1..u, pk', pk2)
	if aggPk.pk2 == nil {
		panic("musig2: BUG: pk2 is nil")
	}
	return keyAggCoeffInternal(aggPk.l, pk, aggPk.pk2), nil
}

// PublicKeyAggregator accumulates PublicKeys, before doing the final
// aggregation and generating an AggregatedPublicKey.
type PublicKeyAggregator struct {
	pks []*secec.PublicKey

	applyKeySort bool
}

// SetKeySort sets if the individual public keys should be sorted during
// the final aggregation step.
func (agg *PublicKeyAggregator) SetKeySort(t bool) *PublicKeyAggregator {
	agg.applyKeySort = t
	return agg
}

// Add adds a PublicKey to the key aggregator.
//
// WARNING: Unless the PublicKeyAggregator is configured to sort the public
// keys, the order in which PublicKeys are added matters.
func (agg *PublicKeyAggregator) Add(pk *secec.PublicKey) error {
	if uint64(len(agg.pks))+1 > maxPublicKeys {
		return errInvalidNumberOfKeys
	}
	if pk == nil {
		panic("musig2: invalid public key")
	}

	agg.pks = append(agg.pks, pk)

	return nil
}

// Aggregate produces an AggregatedPublicKey.  This operation does not affect
// the state of the PublicKeyAggregator.
func (agg *PublicKeyAggregator) Aggregate() (*AggregatedPublicKey, error) {
	pks := agg.pks
	if u := len(pks); uint64(u) > maxPublicKeys || u == 0 {
		return nil, errInvalidNumberOfKeys
	}

	if agg.applyKeySort {
		pks = keySort(pks)
	}

	//
	// KeyAgg - Key Aggregation
	//

	// Let L = HashKeys(pk1..u) (From KeyAggCoeffInternal)
	L := hashKeys(pks)

	// Let pk2 = GetSecondKey(pk_1..u)
	pk2 := getSecondKey(pks)

	// For i = 1 .. u:
	Q := secp256k1.NewIdentityPoint()
	for i := range pks {
		pk := pks[i]

		// Let P_i = cpoint(pk_i); fail if that fails and blame signer
		// i for invalid individual public key.
		//
		// Note/yawning: Since we use sensible data-types rather
		// than byte vectors for public keys, `pks` is guaranteed
		// to be a vector of points on the curve.
		P := pk.Point()

		// Let a_i = KeyAggCoeffInternal(pk_1..u, pk_i, pk2).
		a := keyAggCoeffInternal(L, pk, pk2)

		Q.Add(Q, secp256k1.NewIdentityPoint().ScalarMult(a, P))
	}

	// Let Q = a1 * P1 + a2 * P2 + ... + au * Pu
	//
	// XXX/perf: Add a vartime multiscalar multiply which will outperform
	// the current incremental method of calculating Q, but this operation
	// should be comparatively infrequent, so who cares.

	// Fail if is_infinite(Q).
	if Q.IsIdentity() != 0 {
		return nil, errQIsInfinity
	}

	// Let gacc = 1
	// Let tacc = 0
	// Return keyagg_ctx = (Q, gacc, tacc).
	//
	// Note/yawning: We opt to store extra values that are required
	// as part of the signing/verification process as well so that
	// further calls to getSecondKey (pk2), and HashKeys (L) can
	// be omitted entirely.
	return &AggregatedPublicKey{
		q:    Q,
		gacc: secp256k1.NewScalarFrom(scOne),
		tacc: secp256k1.NewScalar(),
		pks:  pks,
		pk2:  pk2,
		l:    L,
	}, nil
}

// NewPublicKeyAggregator creates an empty PublicKeyAggregator.
func NewPublicKeyAggregator() *PublicKeyAggregator {
	return new(PublicKeyAggregator)
}

// Internal Algorithm HashKeys(pk_1..u).
func hashKeys(pks []*secec.PublicKey) []byte {
	// Return hashKeyAgg list(pk_1 || pk_2 || ... || pk_u)
	h := newTaggedHash(tagKeyAggList)
	for _, pk := range pks {
		_, _ = h.Write(pk.CompressedBytes())
	}
	return h.Sum(nil)
}

// Internal Algorithm GetSecondKey(pk_1..u).
func getSecondKey(pks []*secec.PublicKey) []byte {
	pk1 := pks[0] // The spec starts indexes from 1.

	// For j = 1 .. u:
	for i, pk := range pks {
		if i == 0 {
			continue
		}

		// If pk_j != pk_1:
		if !pk.Equal(pk1) {
			// Return pk_j
			return pks[i].CompressedBytes()
		}
	}

	// Return bytes(33, 0)
	return cIdentityBytes
}

// Internal Algorithm KeyAggCoeffInternal(pk_1..u, pk', pk2).
func keyAggCoeffInternal(l []byte, pkP *secec.PublicKey, pk2 []byte) *secp256k1.Scalar {
	// If pk' = pk2:
	if bytes.Equal(pkP.CompressedBytes(), pk2) {
		// Return 1
		return scOne
	}

	// Let L = HashKeys(pk1..u)
	if l == nil {
		panic("musig2: BUG: L is nil")
	}

	// Return int(hashKeyAgg coefficient(L || pk')) mod n
	b := taggedHash(
		tagKeyAggCoefficient,
		l,                     // L
		pkP.CompressedBytes(), // pk'
	)
	sc, _ := secp256k1.NewScalarFromBytes((*[secp256k1.ScalarSize]byte)(b))

	return sc
}
