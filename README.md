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
- create invalidation Nostr event
- send invalidation event to relay
- listen for invalidation events, verify them

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

## TODO

-


## Contact

Nostr: optout@nostrplebs.com npub1kxgpwh80gp79j0chc925srk6rghw0akggduwau8fwdflslh9jvqqd3lecx


## Sample Output

Some (truncated) sample output

generate
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
```

invalidate
```
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

Verify
```
$ cargo run verify npub195z34nrkuggzmp0dve4ugs85fdkq5q34n3yxaw98zj7afq9cnp2sncwkch npub1vfxu6eandjw8ufpe0wqhhrr4q86z65777vrs66jvx49l2a5fnyvsycs248 npub1en8lkh8c5ljfgjqutpd6q2ht9wy05psguepr7n6958e8yjh0p7wqg3psj9
    Finished dev [unoptimized + debuginfo] target(s) in 0.07s
     Running `target/debug/nip41-proto0 verify npub195z34nrkuggzmp0dve4ugs85fdkq5q34n3yxaw98zj7afq9cnp2sncwkch npub1vfxu6eandjw8ufpe0wqhhrr4q86z65777vrs66jvx49l2a5fnyvsycs248 npub1en8lkh8c5ljfgjqutpd6q2ht9wy05psguepr7n6958e8yjh0p7wqg3psj9`
NIP-41 Proto Zero

WARNING: This is a prototype implementation, use it only with test keys!

Invalid vis     	 npub195z34nrkuggzmp0dve4ugs85fdkq5q34n3yxaw98zj7afq9cnp2sncwkch  (2d051acc76e2102d85ed666bc440f44b6c0a02359c486eb8a714bdd480b89855)
Invalid hid     	 npub1vfxu6eandjw8ufpe0wqhhrr4q86z65777vrs66jvx49l2a5fnyvsycs248  (624dcd67b36c9c7e24397b817b8c7501f42d53def3070d6a4c354bf576899919)
New vis         	 npub1en8lkh8c5ljfgjqutpd6q2ht9wy05psguepr7n6958e8yjh0p7wqg3psj9  (cccffb5cf8a7e494481c585ba02aeb2b88fa0608e6423f4f45a1f2724aef0f9c)
Verification result:  true
```

Listen
```
$ cargo run listen ws://umbrel.local:4848

Connected to relay ws://umbrel.local:4848
Subscribed to relay for invalidation events ...

Received event:  {"content":"key invalidation","created_at":1680473064,"id":"7932f8808754ada34310d7738344a9f279d8944bf49c12e7238d248417b93d89","kind":13,"pubkey":"0333d247f7b0e1dbe7d86cf56a12aeb305a4023832e9cb85c9d7f1cc4b74669b","sig":"bc24dc86f0eb8bb69aed1492cdc803e5a6f8dd9cf78f422767760aafb4664f894913540cfe898053f4a34e6e3281abf084130e7d2f5eeae632ee47b2bb1a8ec0","tags":[["p","cf1bfde74244457f0608ebae4e6c32472e0ee3769b0d7b823d4d558760cd6d2e"],["hidden-key","96653114a1d9ff07e8b4310b93b0a37b541f43f50571f468970fb83d1fe31338"]]}
'P-tag' (invalidated):               npub1eudlme6zg3zh7psgawhyumpjguhqacmknvxhhq3af42cwcxdd5hqr3m0qs  (cf1bfde74244457f0608ebae4e6c32472e0ee3769b0d7b823d4d558760cd6d2e)
'Hidden-key-tag' (invalidated hid):  npub1jejnz99pm8ls0695xy9e8v9r0d2p7sl4q4clg6yhp7ur68lrzvuq8z4k09  (96653114a1d9ff07e8b4310b93b0a37b541f43f50571f468970fb83d1fe31338)
Pubkey (new):                        npub1qveay3lhkrsahe7cdn6k5y4wkvz6gq3cxt5uhpwf6lcucjm5v6dswn37am  (0333d247f7b0e1dbe7d86cf56a12aeb305a4023832e9cb85c9d7f1cc4b74669b)

Invalidate  npub1eudlme6zg3zh7psgawhyumpjguhqacmknvxhhq3af42cwcxdd5hqr3m0qs  in favor of  npub1qveay3lhkrsahe7cdn6k5y4wkvz6gq3cxt5uhpwf6lcucjm5v6dswn37am !

Verification result: true 


Received event:  {"content":"key invalidation","created_at":1680473093,"id":"221a2e767464cca61328031a355c06268291adcff369bdee15df0588dc61c6bb","kind":13,"pubkey":"aad39a3bfd27023d659af43445ee09a84c735b9acac0bbe18498a57514fef383","sig":"d54fb94e4a4a2101e39b36525b42b7b6d791303b350314858610a0d7f5406e218e79a1f29ae3901b7e18a2f4c8630efaabf35e7d29cc0ce62d9d514c393ad4ee","tags":[["p","0333d247f7b0e1dbe7d86cf56a12aeb305a4023832e9cb85c9d7f1cc4b74669b"],["hidden-key","27bcb59fb2c17c25cb57a264b14b97c74466fd5512429bc1d9538196d2623c42"]]}
'P-tag' (invalidated):               npub1qveay3lhkrsahe7cdn6k5y4wkvz6gq3cxt5uhpwf6lcucjm5v6dswn37am  (0333d247f7b0e1dbe7d86cf56a12aeb305a4023832e9cb85c9d7f1cc4b74669b)
'Hidden-key-tag' (invalidated hid):  npub1y77tt8ajc97ztj6h5fjtzjuhcazxdl24zfpfhswe2wqed5nz83pqz863fe  (27bcb59fb2c17c25cb57a264b14b97c74466fd5512429bc1d9538196d2623c42)
Pubkey (new):                        npub14tfe5wlayupr6ev67s6ytmsf4px8xku6etqthcvynzjh29877wps7lpyne  (aad39a3bfd27023d659af43445ee09a84c735b9acac0bbe18498a57514fef383)

Invalidate  npub1qveay3lhkrsahe7cdn6k5y4wkvz6gq3cxt5uhpwf6lcucjm5v6dswn37am  in favor of  npub14tfe5wlayupr6ev67s6ytmsf4px8xku6etqthcvynzjh29877wps7lpyne !

Verification result: true 
```
