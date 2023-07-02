package musig2

import (
	"bytes"
	"errors"
	"math"
	"sort"

	"gitlab.com/yawning/secp256k1-voi"
	"gitlab.com/yawning/secp256k1-voi/secec"
)

const (
	TweakSize = 32 // secp256k1.ScalarSize

	maxPublicKeys = math.MaxUint32

	tagKeyAggList        = "KeyAgg list"
	tagKeyAggCoefficient = "KeyAgg coefficient"
)

var (
	scOne    = secp256k1.NewScalar().One()
	scNegOne = secp256k1.NewScalar().Negate(scOne)

	errInvalidPublicKey    = errors.New("musig2: invalid public key")
	errInvalidNumberOfKeys = errors.New("musig2: invalid number of public keys")
	errInvalidTweak        = errors.New("musig2: invalid tweak")
	errQIsInfinity         = errors.New("musig2: Q is the point at infinity")
)

func KeySort(pks []*secec.PublicKey) ([]*secec.PublicKey, error) {
	u := len(pks)
	if uint64(u) > maxPublicKeys || u == 0 {
		return nil, errInvalidNumberOfKeys
	}

	ret := make([]*secec.PublicKey, 0, u)
	ret = append(ret, pks...)

	// Return pk_1..u sorted in lexicographical order.
	sort.SliceStable(
		ret,
		func(i, j int) bool {
			return bytes.Compare(ret[i].CompressedBytes(), ret[j].CompressedBytes()) < 0
		},
	)

	return ret, nil
}

type KeyAggContext struct {
	q    *secp256k1.Point // Invariant: Not infinity
	tacc *secp256k1.Scalar
	gacc *secp256k1.Scalar

	pks []*secec.PublicKey
}

// XXX: Figure out how to handle KeyAggContext s11n.

func (ctx *KeyAggContext) XBytes() []byte { // XXX/yawning: Maybe private this.
	b, err := ctx.q.XBytes()
	if err != nil {
		panic(err)
	}
	return b
}

func (ctx *KeyAggContext) ApplyTweak(tweak []byte, isXOnlyTweak bool) error {
	if len(tweak) != TweakSize {
		return errInvalidTweak
	}

	// Let (Q, gacc, tacc) = keyagg_ctx

	// If is_xonly_t and not has_even_y(Q):
	g := scOne // Else: Let g = 1
	if isXOnlyTweak && ctx.q.IsYOdd() != 0 {
		// Let g = -1 mod n
		g = scNegOne
	}

	// Let t = int(tweak); fail if t >= n
	t, err := secp256k1.NewScalarFromCanonicalBytes((*[secp256k1.ScalarSize]byte)(tweak))
	if err != nil {
		return errors.Join(errInvalidTweak, err)
	}

	// Let Q' = g * Q + t * G
	qP := secp256k1.NewIdentityPoint().DoubleScalarMultBasepointVartime(t, g, ctx.q)

	// Fail if is_infinite(Q')
	if qP.IsIdentity() != 0 {
		return errQIsInfinity
	}

	// Let gacc' = g * gacc mod n
	ctx.gacc.Multiply(g, ctx.gacc)

	// Let tacc' = t + g * tacc mod n
	ctx.tacc = secp256k1.NewScalar().Sum(t, secp256k1.NewScalar().Product(g, ctx.tacc))

	// Return keyagg_ctx' = (Q', gacc', tacc')
	ctx.q.Set(qP)

	return nil
}

func KeyAgg(pks []*secec.PublicKey) (*KeyAggContext, error) {
	u := len(pks)
	if uint64(u) > maxPublicKeys || u == 0 {
		return nil, errInvalidNumberOfKeys
	}

	// Let pk2 = GetSecondKey(pk_1..u)
	pk2 := getSecondKey(pks)

	// For i = 1 .. u:
	pks2 := make([]*secec.PublicKey, 0, u)
	Q := secp256k1.NewIdentityPoint()
	for i := range pks {
		pk_i := pks[i]

		// Let P_i = cpoint(pk_i); fail if that fails and blame signer
		// i for invalid individual public key.
		//
		// Note/yawning: Since we use sensible data-types rather
		// than byte vectors for public keys, `pks` is guaranteed
		// to be a vector of points on the curve.
		P_i := pk_i.Point()
		if P_i.IsIdentity() != 0 {
			// Should be impossible, but the check is cheap.
			panic(errInvalidPublicKey)
		}

		// Let a_i = KeyAggCoeffInternal(pk_1..u, pk_i, pk2).
		a_i := keyAggCoeffInternal(pks, pk_i, pk2)

		Q_i := secp256k1.NewIdentityPoint().ScalarMult(a_i, P_i) // XXX/perf: Vartime
		Q.Add(Q, Q_i)

		pks2 = append(pks2, pk_i)
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
	return &KeyAggContext{
		q:    Q,
		gacc: secp256k1.NewScalarFrom(scOne),
		tacc: secp256k1.NewScalar(),
		pks:  pks2,
	}, nil
}

// Internal Algorithm HashKeys(pk_1..u)
func hashKeys(pks []*secec.PublicKey) []byte {
	// Return hashKeyAgg list(pk_1 || pk_2 || ... || pk_u)
	h := newTaggedHash(tagKeyAggList)
	for _, pk := range pks {
		_, _ = h.Write(pk.CompressedBytes())
	}
	return h.Sum(nil)
}

// Internal Algorithm GetSecondKey(pk_1..u)
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

// Internal Algorithm KeyAggCoeff(pk_1..u, pk')
func keyAggCoeff(pks []*secec.PublicKey, pkP *secec.PublicKey) *secp256k1.Scalar {
	// Let pk2 = GetSecondKey(pk_1..u):
	pk2 := getSecondKey(pks)

	// Return KeyAggCoeffInternal(pk_1..u, pk', pk2)
	return keyAggCoeffInternal(pks, pkP, pk2)
}

// Internal Algorithm KeyAggCoeffInternal(pk_1..u, pk', pk2)
func keyAggCoeffInternal(pks []*secec.PublicKey, pkP *secec.PublicKey, pk2 []byte) *secp256k1.Scalar {
	// Let L = HashKeys(pk1..u)
	L := hashKeys(pks) // XXX/perf: Cache and reuse this holy shit.

	// If pk' = pk2:
	if bytes.Equal(pkP.CompressedBytes(), pk2) { // XXX/perf: Reorder to before hashing.
		// Return 1
		return scOne
	}

	// Return int(hashKeyAgg coefficient(L || pk')) mod n
	b := taggedHash(
		tagKeyAggCoefficient,
		L,                     // L
		pkP.CompressedBytes(), // pk'
	)
	sc, _ := secp256k1.NewScalarFromBytes((*[secp256k1.ScalarSize]byte)(b))

	return sc
}
