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

Operations:
- obtain current public key / secret key
- generate new set of keys
- generate next level key set from previous level keys
- invalidate: change current key and return keys needed for verification
- verify: verify validity of new key
- Create invalidaiton Nostr event

Details:
- As keys are for Nostr (using Schnorr sig), the type `XOnlyPublicKey` is used for pubkeys. This has the drawback that the parity is missing, and in verification both options have to be tried.


## Building and Running

- Prerequisite: `rust`

- Try following commands:

```
cargo build

cargo run generate
cargo run
cargo run inv
cargo run
```

## Sample Output

```
$ cargo run generate
NIP-41 Proto Zero

WARNING: This is a prototype implementation, use it only with test keys!

State saved
$ 
$ cargo run
KeyState loaded (256 levels)
Level: 0  (out of 256)
Current pubkey:     	 npub185daavrw5jesnxsdd6hluva8em59c369jkpas9nfkm28z58e6hpqrqya6z  (3d1bdeb06ea4b3099a0d6eaffe33a7cee85c47459583d81669b6d47150f9d5c2)
Previous pubkey:    	 None
Current secret key: 	 nsec1l3gan..yd9ah2  (fc51d9ff63..396749)
$
$ cargo run inv
KeyState loaded (256 levels)
Level: 0  (out of 256)
Current pubkey:     	 npub185daavrw5jesnxsdd6hluva8em59c369jkpas9nfkm28z58e6hpqrqya6z  (3d1bdeb06ea4b3099a0d6eaffe33a7cee85c47459583d81669b6d47150f9d5c2)
Previous pubkey:    	 None
Current secret key: 	 nsec1l3gan..yd9ah2  (fc51d9ff63..396749)
Invalidation info:
Invalidated:       	 npub185daavrw5jesnxsdd6hluva8em59c369jkpas9nfkm28z58e6hpqrqya6z  (3d1bdeb06ea4b3099a0d6eaffe33a7cee85c47459583d81669b6d47150f9d5c2)
     hidden:       	 npub195v2xzn03nrcvm7ymmllcrc82xft5h0c40c3jkuz7vjwk4zjayzqn9qtky  (2d18a30a6f8cc7866fc4defffc0f075192ba5df8abf1195b82f324eb5452e904)
        new:       	 npub1zhulyeg2d4d0ujfw2mhnf6pzr4x6eg852tmr8d7msfr53ehd0m5svvky80  (15f9f2650a6d5afe492e56ef34e8221d4daca0f452f633b7db824748e6ed7ee9)
Level: 1  (out of 256)
Current pubkey:     	 npub1zhulyeg2d4d0ujfw2mhnf6pzr4x6eg852tmr8d7msfr53ehd0m5svvky80  (15f9f2650a6d5afe492e56ef34e8221d4daca0f452f633b7db824748e6ed7ee9)
Previous pubkey:    	 npub185daavrw5jesnxsdd6hluva8em59c369jkpas9nfkm28z58e6hpqrqya6z  (3d1bdeb06ea4b3099a0d6eaffe33a7cee85c47459583d81669b6d47150f9d5c2)
Current secret key: 	 nsec1t4a8c..2dtqjj  (5d7a7c04d9..5310e9)
verify?         	 true
Invalidation event: 
{"content":"key invalidation","created_at":1680411807,"id":"7d950460b669b3c32b70145c9cb11343815cbc1b350ab976ed78ea6f30da5540","kind":13,"pubkey":"15f9f2650a6d5afe492e56ef34e8221d4daca0f452f633b7db824748e6ed7ee9","sig":"10d004d1e37a25247849a7093c21a83c3fae39777ac1ace609c4e96832a8708a2332251fe58eee637c43b37718cccbfd897904b7c375825dfb7154850265323a","tags":[["p","3d1bdeb06ea4b3099a0d6eaffe33a7cee85c47459583d81669b6d47150f9d5c2"],["hidden-key","2d18a30a6f8cc7866fc4defffc0f075192ba5df8abf1195b82f324eb5452e904"]]}

State saved
```


## TODO

- Publish invalidation msg to relay
- Option to listen on relay for invalidation events, print & verify them


## Contact

Nostr: optout@nostrplebs.com npub1kxgpwh80gp79j0chc925srk6rghw0akggduwau8fwdflslh9jvqqd3lecx

