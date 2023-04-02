/// Key management logic
///
use bip32::{ChildNumber, XPrv};
use bip39::Mnemonic;
use rand::{thread_rng, RngCore};
use secp256k1::hashes::{sha256, Hash};
use secp256k1::{All, KeyPair, Parity, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};

/// Keys at a given level: a pair of keypairs (visible and hidden)
#[derive(Clone, Copy, Debug)]
struct LevelKeys {
    /// The visible keypair (denoted A)
    vis: KeyPair,
    /// The hidden keypair (denoted A')
    hid: KeyPair,
}

impl LevelKeys {
    pub fn vis_pubkey(&self) -> XOnlyPublicKey {
        self.vis.x_only_public_key().0
    }

    pub fn hid_pubkey(&self) -> XOnlyPublicKey {
        self.hid.x_only_public_key().0
    }
}

/// Default number of pre-generated key level
pub const N_DEFAULT: usize = 256;

/// Complete state of NIP-41 keys
pub struct KeyState {
    /// The N key levels
    k: Vec<LevelKeys>,
    /// Number of discarded levels, initially 0
    l: usize,
    /// The BIP39 entropy used to generate this set
    entropy: Vec<u8>,
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum Error {
    /// There is no invalidated pubkey yet
    #[error("There is no invalidated pubkey yet")]
    NoInvalidatedKey,
    /// No more levels left, ran out of pre-defined keys
    #[error("No more levels left, ran out of pre-defined keys")]
    NoMoreKeyLevels,
    /// Error generating keys from seed
    #[error(transparent)]
    Bip32(#[from] bip32::Error),
    /// Error processing BIP39 mnemonic
    #[error(transparent)]
    Bip39(#[from] bip39::Error),
    /// File not found
    #[error("File not found")]
    FileNotFound,
    /// File parse error
    #[error("File parse error")]
    FileParse,
}

/// Info describing the invalidation of a pubkey
pub struct InvalidationInfo {
    //.. The currently invalidated pubkey (visible)
    pub invalid: XOnlyPublicKey,
    /// The hidden counterpart of the invalidated pubkey
    pub invalid_hid: XOnlyPublicKey,
    /// The new valid pubkey (visible)
    pub new: XOnlyPublicKey,
    /// List of all previous invalidated keys (including the one invalidated just now, plus any earlier ones)
    pub all_invalid: Vec<XOnlyPublicKey>,
}

impl KeyState {
    /// Obtain the current visible pubkey
    pub fn current_pubkey(&self) -> XOnlyPublicKey {
        self.k[self.levels() - 1 - self.l].vis_pubkey()
    }

    /// Obtain the previously used invalid pubkey, if there is one.
    pub fn previous_pubkey(&self) -> Option<XOnlyPublicKey> {
        if self.l == 0 {
            None
        } else {
            Some(self.k[self.levels() - self.l].vis_pubkey())
        }
    }

    /// Obtain the current secret key; security sensitive!
    pub fn current_secret_key(&self) -> SecretKey {
        self.k[self.levels() - 1 - self.l].vis.secret_key()
    }

    pub fn levels(&self) -> usize {
        self.k.len()
    }

    pub fn current_level(&self) -> usize {
        self.l
    }

    pub fn get_entropy(&self) -> Vec<u8> {
        self.entropy.to_owned()
    }

    /// Invalidate the current key; reveal it's secret counterpart,
    /// and (optionally) switch to a new one (the previous one in the pre-generated levels).
    /// Returns these pubkeys:
    /// - the key being invalidated
    /// - its hidden counterpart
    /// - the new key
    /// - a list of all previous invalidated keys (including the one invalidated just now, plus any earlier ones)
    pub fn invalidate(&mut self) -> Result<InvalidationInfo, Error> {
        if self.l >= self.levels() - 1 {
            // No more keys to invalidate to
            return Err(Error::NoMoreKeyLevels);
        }
        // Switch to 'previous' key
        self.l = self.l + 1;
        self.invalidate_prev()
    }

    /// Return the info from the invalidation of the previous pubkey (when the current pubkey was switched to).
    /// If there was no invalidation, error is returned
    pub fn invalidate_prev(&self) -> Result<InvalidationInfo, Error> {
        if self.l == 0 {
            Err(Error::NoInvalidatedKey)
        } else {
            let index_cur = self.levels() - 1 - self.l;
            let index_prev = self.levels() - self.l;
            Ok(InvalidationInfo {
                invalid: self.k[index_prev].vis_pubkey(),
                invalid_hid: self.k[index_prev].hid_pubkey(),
                new: self.k[index_cur].vis_pubkey(),
                all_invalid: self.k[index_prev..self.levels()]
                    .to_vec()
                    .iter()
                    .map(|kl| kl.vis_pubkey())
                    .collect(),
            })
        }
    }
}

/// Key operations
pub struct KeyManager {
    /// Common context for some key operations
    secp: Secp256k1<All>,
}

impl KeyManager {
    pub fn default() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }

    /// Generate a new random state
    pub fn generate_random(&self) -> Result<KeyState, Error> {
        let entropy = Self::generate_random_entropy();
        let mnemonic = Mnemonic::from_entropy(&entropy)?;
        self.generate_from_mnemonic_internal(&mnemonic, 0)
    }

    pub fn generate_random_entropy() -> Vec<u8> {
        let mut entropy: [u8; 32] = [0; 32];
        thread_rng().fill_bytes(&mut entropy);
        entropy.to_vec()
    }

    /// Generate state from a BIP-39 mnemonic (string)
    pub fn generate_from_mnemonic(&self, mnemonic_str: &str) -> Result<KeyState, Error> {
        let mnemonic = Mnemonic::parse(mnemonic_str)?;
        self.generate_from_mnemonic_internal(&mnemonic, 0)
    }

    /// Generate state from a BIP-39 mnemonic entropy
    pub fn generate_from_mnemonic_entropy(
        &self,
        entropy: Vec<u8>,
        current_level: usize,
    ) -> Result<KeyState, Error> {
        let mnemonic = Mnemonic::from_entropy(&entropy)?;
        self.generate_from_mnemonic_internal(&mnemonic, current_level)
    }

    /// Generate state from a BIP-39 mnemonic (struct)
    fn generate_from_mnemonic_internal(
        &self,
        mnemonic: &Mnemonic,
        current_level: usize,
    ) -> Result<KeyState, Error> {
        let seed = mnemonic.to_seed("");
        self.generate_from_master_seed(seed, current_level, mnemonic.to_entropy())
    }

    /// Generate state from a 64-byte master seed
    fn generate_from_master_seed(
        &self,
        master_seed: [u8; 64],
        current_level: usize,
        entropy: Vec<u8>,
    ) -> Result<KeyState, Error> {
        // generate hidden keys HD (hierarchically deterministically, BIP32)
        let mut sk = Vec::new();
        // for optimization, derive common part only once
        let intermediate_key = XPrv::derive_from_path(&master_seed, &"m/44'/1237'/41'".parse()?)?;
        for i in 0..N_DEFAULT {
            // Derive a child key
            let child = intermediate_key.derive_child(ChildNumber::new(i as u32, true)?)?;
            sk.push(SecretKey::from_slice(&child.private_key().to_bytes()).unwrap());
        }
        self.generate_levels_internal(sk, current_level, entropy)
    }

    /// Generate state, hidden secret keys are supplied. Their number also specifies the levels.
    fn generate_levels_internal(
        &self,
        sk: Vec<SecretKey>,
        current_level: usize,
        entropy: Vec<u8>,
    ) -> Result<KeyState, Error> {
        let mut keys: Vec<LevelKeys> = Vec::new();

        let sk_0_hid = sk[0];
        let sk_0_vis = sk_0_hid.clone();
        let mut current = LevelKeys {
            vis: KeyPair::from_secret_key(&self.secp, &sk_0_vis),
            hid: KeyPair::from_secret_key(&self.secp, &sk_0_hid),
        };
        keys.push(current);

        let levels = sk.len();
        for i in 1..levels {
            let next = self.next_level(&current, &sk[i]);
            keys.push(next);
            current = next;
        }

        Ok(KeyState {
            k: keys,
            l: current_level,
            entropy,
        })
    }

    /// Compute the hash of the concatenation of two public keys (X coordinates)
    fn hash_of_two_pubkeys(pk1: &XOnlyPublicKey, pk2: &XOnlyPublicKey) -> [u8; 32] {
        let x2 = pk2.serialize();
        let mut bytes = pk1.serialize().to_vec();
        bytes.append(&mut x2.to_vec());
        sha256::Hash::hash(bytes.as_slice()).to_byte_array()
    }

    /// Generate next level from previous one; hidden key is also an input
    fn next_level(&self, prev: &LevelKeys, sk_next_hid: &SecretKey) -> LevelKeys {
        let hash = Self::hash_of_two_pubkeys(
            &prev.vis_pubkey(),
            &sk_next_hid.x_only_public_key(&self.secp).0,
        );
        // Compute new secret key by adding hash value (scalar addition) (sk1 = sk1' + hash)
        let diff = Scalar::from_be_bytes(hash).unwrap();
        let sk_next_vis = sk_next_hid.add_tweak(&diff).unwrap();
        LevelKeys {
            vis: KeyPair::from_secret_key(&self.secp, &sk_next_vis),
            hid: KeyPair::from_secret_key(&self.secp, &sk_next_hid),
        }
    }

    /// Perform verification of a newly rotated key
    pub fn verify(
        &self,
        next_visible: &XOnlyPublicKey,
        next_hidden: &XOnlyPublicKey,
        prev_visible: &XOnlyPublicKey,
    ) -> bool {
        let hash = Self::hash_of_two_pubkeys(&prev_visible, &next_hidden);
        // Compute new pubkey by adding hash value (point addition) (pk1 = pk1' + hash)
        // We try two options, with the two parity options
        let diff = Scalar::from_be_bytes(hash).unwrap();
        let pk_next_odd = next_hidden
            .public_key(Parity::Odd)
            .add_exp_tweak(&self.secp, &diff)
            .unwrap()
            .x_only_public_key()
            .0;
        let pk_next_even = next_hidden
            .public_key(Parity::Even)
            .add_exp_tweak(&self.secp, &diff)
            .unwrap()
            .x_only_public_key()
            .0;
        // Compare
        (pk_next_odd == *next_visible) || (pk_next_even == *next_visible)
    }
}

#[cfg(test)]
mod test {
    use super::{Error, KeyManager, LevelKeys};
    use secp256k1::{KeyPair, Scalar, Secp256k1, SecretKey};

    /// Some constant, random-generated keys
    const KEY1: &str = "0b441d3662962b4060e15801da6edbf017c14574a03ce8076ceb565fbdad12c1";
    const KEY2: &str = "c6431e41a67ca926e2c1b7356b9266642d3e039df9f3b428586910305c522635";
    const KEY3: &str = "26d5cf30786a9d2c6f6ef3dffa687257d5ec3baae9e30a3f74d96bbae192f3a7";
    const SEED1: &str = "4a452d8daa6e997ff65bf681262a61b5cadb0ec65989adc594f52cabc96747a19fc6b21bc4db3d9dad553beadc56156b38c377a92d6952dcd2f5d2fe874a2985";
    const MNEMO1: &str = "oil oil oil oil oil oil oil oil oil oil oil oil";

    fn default_keyset_1_and_2(mgr: &KeyManager) -> LevelKeys {
        LevelKeys {
            vis: KeyPair::from_secret_key(
                &mgr.secp,
                &SecretKey::from_slice(&hex::decode(KEY1).unwrap()).unwrap(),
            ),
            hid: KeyPair::from_secret_key(
                &mgr.secp,
                &SecretKey::from_slice(&hex::decode(KEY2).unwrap()).unwrap(),
            ),
        }
    }

    #[test]
    fn generate_random_get_current() {
        let mgr = KeyManager::default();
        let state = mgr.generate_random().unwrap();

        assert_eq!(state.levels(), 256);

        let sk = state.current_secret_key();
        let pk = state.current_pubkey();
        // check sk-pk
        assert_eq!(
            sk.x_only_public_key(&mgr.secp).0.serialize(),
            pk.serialize()
        );
    }

    #[test]
    fn invalidate_and_verify() {
        let mgr = KeyManager::default();
        let mut state = mgr.generate_random().unwrap();
        let pre_curr = state.current_pubkey();

        // no invalidated yet
        assert_eq!(
            state.invalidate_prev().err().unwrap(),
            Error::NoInvalidatedKey
        );

        // do invalidate current key
        let inv_info = state.invalidate().unwrap();
        assert_eq!(inv_info.invalid, pre_curr);
        assert_eq!(inv_info.all_invalid.len(), 1);
        assert_eq!(inv_info.all_invalid[0], pre_curr);
        // current has changed
        assert_eq!(state.current_pubkey(), inv_info.new);

        // verify
        let verify_result = mgr.verify(&inv_info.invalid, &inv_info.invalid_hid, &inv_info.new);
        assert!(verify_result);

        // Same invalidation info can be retrieved
        let inv_info2 = state.invalidate_prev().unwrap();
        assert_eq!(inv_info2.new, inv_info.new);
    }

    #[test]
    fn invalidate_and_verify_many() {
        let mgr = KeyManager::default();
        let mut state = mgr.generate_random().unwrap();
        assert_eq!(state.levels(), 256);
        // do 255 invalidates
        for i in 0..255 {
            let pk = state.current_pubkey();
            let inv_info = state.invalidate().unwrap();
            assert_eq!(inv_info.invalid, pk);
            assert_eq!(inv_info.all_invalid.len(), i + 1);
            // verify
            let verify_result = mgr.verify(&inv_info.invalid, &inv_info.invalid_hid, &inv_info.new);
            assert!(verify_result);
        }
        // try another one, should fail
        assert_eq!(state.invalidate().err().unwrap(), Error::NoMoreKeyLevels);
    }

    #[test]
    fn verify() {
        let mgr = KeyManager::default();
        let current = default_keyset_1_and_2(&mgr);
        let sk_next_t = SecretKey::from_slice(&hex::decode(KEY3).unwrap()).unwrap();

        let next = mgr.next_level(&current, &sk_next_t);

        let verify_result = mgr.verify(
            &next.vis_pubkey(),
            &next.hid_pubkey(),
            &current.vis_pubkey(),
        );
        assert!(verify_result);

        // Invoking verify with wrong value should return false
        assert!(!mgr.verify(
            &next.vis_pubkey(),
            &next.hid_pubkey(),
            // this is the wrong value here
            &current.hid_pubkey(),
        ));
    }

    #[test]
    fn generate_mnemonic() {
        let mgr = KeyManager::default();
        let state1 = mgr.generate_from_mnemonic(MNEMO1).unwrap();

        let pk1 = state1.current_pubkey();
        assert_eq!(
            hex::encode(pk1.serialize()),
            "2d051acc76e2102d85ed666bc440f44b6c0a02359c486eb8a714bdd480b89855"
        );

        // Generate again. result should be same (deterministic)
        let state2 = mgr.generate_from_mnemonic(MNEMO1).unwrap();
        let pk2 = state2.current_pubkey();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn generate_master_seed() {
        let master_seed: [u8; 64] = hex::decode(SEED1).unwrap().try_into().unwrap();

        let mgr = KeyManager::default();
        let state1 = mgr
            .generate_from_master_seed(master_seed, 0, Vec::new())
            .unwrap();

        let pk1 = state1.current_pubkey();
        assert_eq!(
            hex::encode(pk1.serialize()),
            "ed38c53f8e4eadaebc796b40e97ffb8808f78798d5219b9dfe5e341e89e411ee"
        );

        // Generate again. result should be same (deterministic)
        let state2 = mgr
            .generate_from_master_seed(master_seed, 0, Vec::new())
            .unwrap();
        let pk2 = state2.current_pubkey();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn manager_next_level() {
        let mgr = KeyManager::default();
        let current = default_keyset_1_and_2(&mgr);
        let sk_next_t = SecretKey::from_slice(&hex::decode(KEY3).unwrap()).unwrap();

        let next = mgr.next_level(&current, &sk_next_t);
        assert_eq!(
            hex::encode(next.vis.secret_key().secret_bytes()),
            "bf0c756639fa5542a5839ab6825258f21056a72cabec222a50b9e7b07a1eb09e"
        );
        assert_eq!(
            hex::encode(next.hid.secret_key().secret_bytes()),
            "26d5cf30786a9d2c6f6ef3dffa687257d5ec3baae9e30a3f74d96bbae192f3a7"
        );
    }

    #[test]
    fn hash_of_two_pubkeys() {
        let mgr = KeyManager::default();
        let keys = default_keyset_1_and_2(&mgr);

        let hash = KeyManager::hash_of_two_pubkeys(&keys.vis_pubkey(), &keys.hid_pubkey());
        assert_eq!(
            hex::encode(hash),
            "6d19c6173b3d59014fab1ec77d4dad98f5cd515d74b0512aab71b3c38a806deb"
        );
    }

    /// Test derived secret keys by addition, derived public keys by addition
    fn test_tweaked_secret_and_public_keys(sk1: &SecretKey, diff: &Scalar) {
        let secp = Secp256k1::new();
        // public key
        let pk1 = sk1.x_only_public_key(&secp).0;

        // tweaked secret key
        let sk2 = sk1.add_tweak(diff).unwrap();
        // its public key
        let pk2 = sk2.x_only_public_key(&secp).0;

        // tweaked public key
        let pk3 = pk1.add_tweak(&secp, diff).unwrap().0;
        // the two should match
        assert_eq!(pk2, pk3);
    }

    #[test]
    fn tweaked_secret_and_public_keys_1_detailed() {
        // original secret key
        let sk1 = SecretKey::from_slice(&hex::decode(KEY1).unwrap()).unwrap();
        assert_eq!(
            hex::encode(sk1.secret_bytes()),
            "0b441d3662962b4060e15801da6edbf017c14574a03ce8076ceb565fbdad12c1"
        );

        let secp = Secp256k1::new();
        // its public key
        let pk1 = sk1.x_only_public_key(&secp).0;
        assert_eq!(
            hex::encode(&pk1.serialize()),
            "3053cfbe7bedc6a9ef920d91e11b9c8c5bb9270bb9546e14ca3eeef624d78677"
        );

        let diff = &Scalar::ONE;

        // tweaked secret key
        let sk2 = sk1.add_tweak(diff).unwrap();
        assert_eq!(
            hex::encode(sk2.secret_bytes()),
            "0b441d3662962b4060e15801da6edbf017c14574a03ce8076ceb565fbdad12c2"
        );
        // its public key
        let pk2 = sk2.x_only_public_key(&secp).0;
        assert_eq!(
            hex::encode(&pk2.serialize()),
            "e00d187b6f23ce28dad827ad336a3fb885146c1679c0d856cb0d4f094ae057c0"
        );

        // tweaked public key
        let pk3 = pk1.add_tweak(&secp, diff).unwrap().0;
        assert_eq!(
            hex::encode(&pk3.serialize()),
            "e00d187b6f23ce28dad827ad336a3fb885146c1679c0d856cb0d4f094ae057c0"
        );
        // the two should be the same
        assert_eq!(pk2, pk3);
    }

    #[test]
    fn tweaked_secret_and_public_keys() {
        let sk1 = SecretKey::from_slice(&hex::decode(KEY1).unwrap()).unwrap();

        test_tweaked_secret_and_public_keys(&sk1, &Scalar::ZERO);
        test_tweaked_secret_and_public_keys(&sk1, &Scalar::ONE);
        test_tweaked_secret_and_public_keys(
            &sk1,
            &Scalar::from_be_bytes(
                hex::decode("0000000000000000000000000000000000000000000000000000000000000002")
                    .unwrap()
                    .try_into()
                    .unwrap_or_else(|_v| panic!("Wrong vector size")),
            )
            .unwrap(),
        );
        test_tweaked_secret_and_public_keys(
            &sk1,
            &Scalar::from_be_bytes(
                hex::decode("0000000000000000000000000000000000000000000000000000000000000204")
                    .unwrap()
                    .try_into()
                    .unwrap_or_else(|_v| panic!("Wrong vector size")),
            )
            .unwrap(),
        );
    }
}
