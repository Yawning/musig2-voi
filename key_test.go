package musig2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func testKeySortVectors(t *testing.T) {
	var testVectors tvHeader
	unpackTestVectors(t, "testdata/key_sort_vectors.json", &testVectors)

	unsorted, errs := testVectors.PubKeys()
	require.Len(t, unsorted, len(errs))
	for i := range unsorted {
		require.NotNil(t, unsorted[i])
		require.NoError(t, errs[i])
	}

	expected := testVectors.SortedPubKeys(t)
	require.Len(t, expected, len(unsorted))

	sorted, err := KeySort(unsorted)
	require.NoError(t, err, "KeySort")
	require.Len(t, sorted, len(expected))

	for i, pk := range sorted {
		require.True(t, expected[i].Equal(pk), "[%d]: expected != sorted", i)
	}
}

func testKeyAggVectors(t *testing.T) {
	var testVectors tvHeader
	unpackTestVectors(t, "testdata/key_agg_vectors.json", &testVectors)

	for i := range testVectors.Valid {
		vec := &testVectors.Valid[i]
		t.Run(fmt.Sprintf("Valid %d", i), func(t *testing.T) {
			if vec.Comment != "" {
				t.Log(vec.Comment)
			}

			ctx := testVectors.KeyAggContext(t, vec.KeyIndices)

			require.Equal(t, vec.Expected(), ctx.XBytes())
		})
	}

	const (
		tweakErrRange = "The tweak must be less than n."
		tweakErrQInf  = "The result of tweaking cannot be infinity."
	)

	for i := range testVectors.Error {
		vec := &testVectors.Error[i]
		t.Run(fmt.Sprintf("Error %d", i), func(t *testing.T) {
			if vec.Comment != "" {
				t.Log(vec.Comment)
			}

			tvPubKeys, errs := testVectors.PubKeys()
			tweaks := testVectors.Tweaks()

			// If the test case failure is due to an invalid contribution
			// this is something that our implementation catches when the
			// public key is deserialized.
			if vec.Error.Type == typeInvalidContribution {
				require.Equal(t, contribPubKey, vec.Error.Contrib)
				idx := vec.KeyIndices[*vec.Error.Signer]
				require.Nil(t, tvPubKeys[idx])
				require.Error(t, errs[idx])
				return
			}

			// Otherwise the failure happens during applying the tweak.
			ctx := testVectors.KeyAggContext(t, vec.KeyIndices)
			require.Equal(t, typeValue, vec.Error.Type)

			// The datastructure supports more than one tweak, but
			// current testcases only have one, so be lazy.
			tweakIdx := vec.TweakIndices[0]
			isXOnlyTweak := vec.IsXOnly[0]

			err := ctx.ApplyTweak(tweaks[tweakIdx], isXOnlyTweak)
			switch vec.Error.Message {
			case tweakErrRange:
				require.ErrorIs(t, err, errInvalidTweak)
			case tweakErrQInf:
				require.ErrorIs(t, err, errQIsInfinity)
			default:
				t.Fatalf("unsupported test case message: '%s'", vec.Error.Message)
			}
		})
	}
}
