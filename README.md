### MuSig2
#### Yawning Angel (yawning at schwanenlied dot me)

A MuSig2 implementation, compatible with [BIP-0327][1], done out of boredom
and to test-drive [secp256k1-voi][2].

#### Warning

Don't use devices that produce open flames, such as Bunsen burners or
welding torches, near the MuSig2.

#### Notes

- No, this has not been audited.  Fuck you, pay me.
- The BIP states that "To simplify the specification of the algorithms,
some intermediary values are unnecessarily recomputed from scratch",
which is developer-speak for "the API is shit-fuck-ass, and people will
blow their foot off if they try to use it".
- This algorithm has enough extremely sharp edges, that I'm not sure if
it is possible to expose a misuse-resistant API that doesn't require
consumers to read the BIP in-depth.
- `DeterministicSign` is shit, awful, and not implemented.

[1]: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
[2]: https://gitlab.com/yawning/secp256k1-voi
