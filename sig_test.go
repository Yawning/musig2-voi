package musig2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
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

			pkAggregator := testVectors.PublicKeyAggregator(t, vec.KeyIndices)
			aggPk, err := pkAggregator.Aggregate()
			require.NoError(t, err)

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

			nonceAggregator := testVectors.PublicNonceAggregator(t, vec.NonceIndices)
			aggNonce, err := nonceAggregator.Aggregate()
			require.NoError(t, err)

			aggNonces, _ := testVectors.AggNonces()
			expectedAggNonce := aggNonces[vec.AggNonceIndex]
			require.EqualValues(t, expectedAggNonce.Bytes(), aggNonce.Bytes())

			partialSig, err := Sign(sk, aggPk, secNonce, aggNonce, msg)
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

			aggregator := testVectors.PublicKeyAggregator(t, vec.KeyIndices)
			aggPk, err := aggregator.Aggregate()
			require.NoError(t, err)

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

			partialSig, err := Sign(sk, aggPk, secNonce, aggNonce, msg)
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

			pkAggregator := testVectors.PublicKeyAggregator(t, vec.KeyIndices)
			aggPk, err := pkAggregator.Aggregate()
			require.NoError(t, err)

			tweaks := testVectors.Tweaks()
			for ii, idx := range vec.TweakIndices {
				tweak, isXOnly := tweaks[idx], vec.IsXOnly[ii]
				err := aggPk.ApplyTweak(tweak, isXOnly)
				require.NoError(t, err, "ApplyTweak")
			}

			nonceAggregator := testVectors.PublicNonceAggregator(t, vec.NonceIndices)
			aggNonce, err := nonceAggregator.Aggregate()
			require.NoError(t, err)

			expectedAggNonce := vec.AggNonce(t)
			require.EqualValues(t, expectedAggNonce.Bytes(), aggNonce.Bytes())

			sigAggregator := NewPartialSignatureAggregator(aggPk, aggNonce, msg)
			hdrPSigs, errs := testVectors.PartialSigs()
			for _, idx := range vec.PSigIndices {
				require.NoError(t, errs[idx])
				err = sigAggregator.Add(hdrPSigs[idx])
				require.NoError(t, err)
			}

			sig, err := sigAggregator.Aggregate()
			require.NoError(t, err)

			// So, the claim/whole point of this MuSig2 nonsense is
			// that aggregated signatures are compatible with BIP-340
			// Schnorr signatures, so test that as well.

			ok := aggPk.Schnorr().Verify(msg, sig)
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
