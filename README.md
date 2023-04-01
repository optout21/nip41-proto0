# NIP-41 Key Invalidation Prototype

NIP-41 is a proposal for a scheme whereby a Nostr identity key can be invalidated to a new one safely.
https://github.com/nostr-protocol/nips/pull/158

__WARNING:__ This is a prototype implementation, use it only with test keys!

## Details

Terms:
- Key state: all predefined keys, plus the index of the currently valid keys
- Level: one element in the set of keys pre-generated iteratively
- Visible, denoted `vis`: the vis (public) keyset of a level, denoted e.g. `A`
- Hidden, denoted `hid`: the hid (secret) keyset of a level, denoted e.g. `A'`


Details:
- As keys are for Nostr (using Schnorr sig), the type `XOnlyPublicKey` is used for pubkeys. This has the drawback that the parity is missing, and in verification both options have to be tried.


Operations:
- obtain current public key / secret key
- generate new set of keys
- generate next level key set from previous level keys
- invalidate: change current key and return keys needed for verification
- verify: verify validity of new key


## Building and Running

- Prerequisite: `rust`

- Try following commands:

```
cargo build

cargo run generate
cargo run
cargo run drop
cargo run
```


## TODO

- Create Invalidation message
- Cmdline options: import, prompt for mnemonic
- Cmdline options: verify, requires 3 pubkeys


## Contact

Nostr: optout@nostrplebs.com npub1kxgpwh80gp79j0chc925srk6rghw0akggduwau8fwdflslh9jvqqd3lecx

