package musig2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/yawning/secp256k1-voi/secec/bitcoin"
)

func testSignVectors(t *testing.T) {
	var testVectors struct {
		tvHeader
		SignError []tvErrorCase `json:"sign_error_test_cases"`
	}
	unpackTestVectors(t, "testdata/sign_verify_vectors.json", &testVectors)

	for i := range testVectors.Valid {
		vec := &testVectors.Valid[i]
		t.Run(fmt.Sprintf("Valid %d", i), func(t *testing.T) {
			if vec.Comment != "" {
				t.Log(vec.Comment)
			}

			sk := testVectors.SecKey(t)

			ctx := testVectors.KeyAggContext(t, vec.KeyIndices)

			msg := testVectors.Messages()[vec.MsgIndex]
			require.NotNil(t, msg)

			// WARNING: Don't ever do this. Tbh, including this in test
			// vectors/test cases is fucking moronic, despite the warning
			// in the reference python code.
			//
			// I get that it's the crypto winter, but I didn't know that
			// things were so tight that they can't spare (at most)
			// 97-bytes per valid test case.
			secNonces, _ := testVectors.SecNonces()
			secNonce := secNonces[0]

			aggNonces, _ := testVectors.AggNonces()
			expectedAggNonce := aggNonces[vec.AggNonceIndex]
			aggNonce := testVectors.AggNonce(t, vec.NonceIndices)
			require.EqualValues(t, expectedAggNonce.Bytes(), aggNonce.Bytes())

			partialSig, err := Sign(sk, ctx, secNonce, aggNonce, msg)
			require.NoError(t, err, "Sign")
			require.EqualValues(t, vec.Expected(), partialSig.Bytes())
		})
	}

	for i := range testVectors.SignError {
		vec := &testVectors.SignError[i]
		t.Run(fmt.Sprintf("Error %d", i), func(t *testing.T) {
			if vec.Comment != "" {
				t.Log(vec.Comment)
			}

			sk := testVectors.SecKey(t)

			if vec.Error.Is(typeInvalidContribution, contribPubKey) {
				pubKeys, errs := testVectors.PubKeys()
				t.Log(pubKeys)

				idx := vec.KeyIndices[*vec.Error.Signer]
				require.Nil(t, pubKeys[idx])
				require.Error(t, errs[idx])
				return
			}

			ctx := testVectors.KeyAggContext(t, vec.KeyIndices)

			msg := testVectors.Messages()[vec.MsgIndex]
			require.NotNil(t, msg)

			// Sigh, just... no (See the warning in the successful case).
			secNonces, errs := testVectors.SecNonces()
			secNonce := secNonces[vec.SecNonceIndex]
			if secNonce == nil {
				require.Equal(t, typeValue, vec.Error.Type)
				require.ErrorIs(t, errs[vec.SecNonceIndex], errKIsZero)
				return
			}

			aggNonces, errs := testVectors.AggNonces()
			if vec.Error.Is(typeInvalidContribution, contribAggNonce) {
				idx := vec.AggNonceIndex
				require.Nil(t, aggNonces[idx])
				require.Error(t, errs[idx])
				return
			}
			aggNonce := aggNonces[vec.AggNonceIndex]

			partialSig, err := Sign(sk, ctx, secNonce, aggNonce, msg)
			require.Error(t, err, "Sign")
			require.Nil(t, partialSig)
		})
	}
}

func testPartialSigAggVectors(t *testing.T) {
	var testVectors tvHeader
	unpackTestVectors(t, "testdata/sig_agg_vectors.json", &testVectors)

	msg := testVectors.Msg()

	for i := range testVectors.Valid {
		vec := &testVectors.Valid[i]
		t.Run(fmt.Sprintf("Valid %d", i), func(t *testing.T) {
			if vec.Comment != "" {
				t.Log(vec.Comment)
			}

			ctx := testVectors.KeyAggContext(t, vec.KeyIndices)

			tweaks := testVectors.Tweaks()
			for ii, idx := range vec.TweakIndices {
				tweak, isXOnly := tweaks[idx], vec.IsXOnly[ii]
				err := ctx.ApplyTweak(tweak, isXOnly)
				require.NoError(t, err, "ApplyTweak")
			}

			expectedAggNonce := vec.AggNonce(t)
			aggNonce := testVectors.AggNonce(t, vec.NonceIndices)
			require.EqualValues(t, expectedAggNonce.Bytes(), aggNonce.Bytes())

			hdrPSigs, errs := testVectors.PartialSigs()
			pSigs := make([]*PartialSignature, 0, len(vec.PSigIndices))
			for _, idx := range vec.PSigIndices {
				psig, err := hdrPSigs[idx], errs[idx]
				require.NoError(t, err)
				pSigs = append(pSigs, psig)
			}

			aggSig, err := PartialSigAgg(ctx, aggNonce, msg, pSigs)
			require.NoError(t, err, "PartialSigAgg")
			require.Equal(t, vec.Expected(), aggSig)

			// So, the claim/whole point of this MuSig2 nonsense is
			// that aggregated signatures are compatible with BIP-340
			// Schnorr signatures, so test that as well.

			schnorrPub, err := bitcoin.NewSchnorrPublicKey(ctx.XBytes())
			require.NoError(t, err, "NewSchnorrPublicKey")

			ok := schnorrPub.Verify(msg, aggSig)
			require.True(t, ok, "SchnorrPublicKey.Verify")
		})
	}

	for i := range testVectors.Error {
		vec := &testVectors.Error[i]
		t.Run(fmt.Sprintf("Error %d", i), func(t *testing.T) {
			// There's only one test case, and it's signature s11n
			// related. Naturally, unlike all the other test cases,
			// the `error` is missing `contrib`, because fuck you.
			require.True(t, vec.Error.Is(typeInvalidContribution, ""))
			hdrPSigs, errs := testVectors.PartialSigs()
			idx := vec.PSigIndices[*vec.Error.Signer]
			require.Nil(t, hdrPSigs[idx])
			require.Error(t, errs[idx])
		})
	}
}
