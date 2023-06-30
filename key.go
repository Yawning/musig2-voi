package musig2

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"math"
	"sort"

	"gitlab.com/yawning/secp256k1-voi"
	"gitlab.com/yawning/secp256k1-voi/secec"
)

const (
	PrivateKeySize = 32 // secp256k1.ScalarSize
	PublicKeySize  = 33 // secp256k1.CompressedPointSize
	TweakSize      = 32 // secp256k1.ScalarSize

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

	pkInf = &PublicKey{
		p:      secp256k1.NewIdentityPoint(),
		pBytes: make([]byte, PublicKeySize),
	}
)

type PrivateKey struct {
	dPrime *secp256k1.Scalar
	pk     *PublicKey
}

func (k *PrivateKey) Bytes() []byte {
	return k.dPrime.Bytes()
}

func NewPrivateKey(b []byte) (*PrivateKey, error) {
	ecK, err := secec.NewPrivateKey(b)
	if err != nil {
		return nil, err
	}

	ecPk := ecK.PublicKey()

	return &PrivateKey{
		dPrime: ecK.Scalar(),
		pk: &PublicKey{
			p:      ecPk.Point(),
			pBytes: ecPk.CompressedBytes(),
		},
	}, nil
}

type PublicKey struct {
	p      *secp256k1.Point // Invariant: Not infinity
	pBytes []byte
}

func (k *PublicKey) Bytes() []byte {
	if k.pBytes == nil {
		panic(errInvalidPublicKey)
	}
	return bytes.Clone(k.pBytes)
}

func (k *PublicKey) Equal(other *PublicKey) bool {
	return subtle.ConstantTimeCompare(k.pBytes, other.pBytes) == 1
}

func (k *PublicKey) clone() *PublicKey {
	if k.pBytes == nil {
		panic(errInvalidPublicKey)
	}

	return &PublicKey{
		p:      secp256k1.NewPointFrom(k.p),
		pBytes: bytes.Clone(k.pBytes),
	}
}

func NewPublicKey(b []byte) (*PublicKey, error) {
	p, err := secp256k1.NewIdentityPoint().SetCompressedBytes(b)
	if err != nil {
		return nil, errors.Join(errInvalidPublicKey, err)
	}

	return &PublicKey{
		p:      p,
		pBytes: bytes.Clone(b),
	}, nil
}

func KeySort(pks []*PublicKey) ([]*PublicKey, error) {
	u := len(pks)
	if uint64(u) > maxPublicKeys || u == 0 {
		return nil, errInvalidNumberOfKeys
	}

	ret := make([]*PublicKey, 0, u)
	ret = append(ret, pks...)

	// Return pk_1..u sorted in lexicographical order.
	sort.SliceStable(
		ret,
		func(i, j int) bool {
			return bytes.Compare(ret[i].pBytes, ret[j].pBytes) < 0
		},
	)

	return ret, nil
}

type KeyAggContext struct {
	q    *secp256k1.Point // Invariant: Not infinity
	tacc *secp256k1.Scalar
	gacc *secp256k1.Scalar

	pks []*PublicKey
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
	ctx.tacc = sumScalars(t, mulScalars(g, ctx.tacc))

	// Return keyagg_ctx' = (Q', gacc', tacc')
	ctx.q.Set(qP)

	return nil
}

func KeyAgg(pks []*PublicKey) (*KeyAggContext, error) {
	u := len(pks)
	if uint64(u) > maxPublicKeys || u == 0 {
		return nil, errInvalidNumberOfKeys
	}

	// Let pk2 = GetSecondKey(pk_1..u)
	pk2 := getSecondKey(pks)

	// For i = 1 .. u:
	pks2 := make([]*PublicKey, 0, u)
	Q := secp256k1.NewIdentityPoint()
	for i := range pks {
		pk_i := pks[i]

		// Let P_i = cpoint(pk_i); fail if that fails and blame signer
		// i for invalid individual public key.
		//
		// Note/yawning: Since we use sensible data-types rather
		// than byte vectors for public keys, `pks` is guaranteed
		// to be a vector of points on the curve.
		P_i := pk_i.p
		if P_i.IsIdentity() != 0 {
			// Should be impossible, but the check is cheap.
			panic(errInvalidPublicKey)
		}

		// Let a_i = KeyAggCoeffInternal(pk_1..u, pk_i, pk2).
		a_i := keyAggCoeffInternal(pks, pk_i, pk2)

		Q_i := secp256k1.NewIdentityPoint().ScalarMult(a_i, P_i) // XXX/perf: Vartime
		Q.Add(Q, Q_i)

		pks2 = append(pks2, pk_i.clone())
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
func hashKeys(pks []*PublicKey) []byte {
	// Return hashKeyAgg list(pk_1 || pk_2 || ... || pk_u)
	h := newTaggedHash(tagKeyAggList)
	for _, pk := range pks {
		_, _ = h.Write(pk.pBytes)
	}
	return h.Sum(nil)
}

// Internal Algorithm GetSecondKey(pk_1..u)
func getSecondKey(pks []*PublicKey) *PublicKey {
	pk1 := pks[0] // The spec starts indexes from 1.

	// For j = 1 .. u:
	for i, pk := range pks {
		if i == 0 {
			continue
		}

		// If pk_j != pk_1:
		if !pk.Equal(pk1) {
			// Return pk_j
			return pks[i]
		}
	}

	// Return bytes(33, 0)
	return pkInf
}

// Internal Algorithm KeyAggCoeff(pk_1..u, pk')
func keyAggCoeff(pks []*PublicKey, pkP *PublicKey) *secp256k1.Scalar {
	// Let pk2 = GetSecondKey(pk_1..u):
	pk2 := getSecondKey(pks)

	// Return KeyAggCoeffInternal(pk_1..u, pk', pk2)
	return keyAggCoeffInternal(pks, pkP, pk2)
}

// Internal Algorithm KeyAggCoeffInternal(pk_1..u, pk', pk2)
func keyAggCoeffInternal(pks []*PublicKey, pkP, pk2 *PublicKey) *secp256k1.Scalar {
	// Let L = HashKeys(pk1..u)
	L := hashKeys(pks) // XXX/perf: Cache and reuse this holy shit.

	// If pk' = pk2:
	if pkP.Equal(pk2) { // XXX/perf: Reorder to before hashing.
		// Return 1
		return scOne
	}

	// Return int(hashKeyAgg coefficient(L || pk')) mod n
	b := taggedHash(
		tagKeyAggCoefficient,
		L,          // L
		pkP.pBytes, // pk'
	)
	sc, _ := secp256k1.NewScalarFromBytes((*[secp256k1.ScalarSize]byte)(b))

	return sc
}
