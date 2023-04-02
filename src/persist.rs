/// Persist state to a file.
/// File from local dir is used
/// BIP39 entropy is saved (as hex string)
use crate::keys::{Error, KeyManager, KeyState};
use std::fs;

const FILE_NAME: &str = "./keyset.txt";

pub struct Persist {}

impl Persist {
    pub fn save(state: &KeyState) -> Result<(), Error> {
        let hexstr = hex::encode(state.get_entropy());
        let contents = format!("{} {}", hexstr, state.current_level());
        fs::write(FILE_NAME, contents)?;
        Ok(())
    }

    pub fn load() -> Result<KeyState, Error> {
        let contents = fs::read_to_string(FILE_NAME)?;
        let split = contents.split(' ').collect::<Vec<&str>>();
        if split.len() < 2 {
            return Err(Error::FileParse);
        }
        let entropy = hex::decode(split[0]).map_err(|_| Error::FileParse)?;
        let level = split[1].parse::<usize>().map_err(|_| Error::FileParse)?;
        let mgr = KeyManager::default();
        let state = mgr.generate_from_mnemonic_entropy(entropy, level)?;
        Ok(state)
    }
}
