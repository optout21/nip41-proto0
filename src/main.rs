mod keys;
mod nostr;
mod persist;

use crate::keys::{KeyManager, KeyState};
use crate::nostr::Nip41;
use crate::persist::Persist;
use ::nostr::prelude::ToBech32;
use secp256k1::{SecretKey, XOnlyPublicKey};
use std::env;
use std::string::ToString;

fn load_state() -> Option<KeyState> {
    match Persist::load() {
        Err(e) => {
            println!("Error: Could not load state {}", e);
            None
        }
        Ok(state) => {
            println!("KeyState loaded ({} levels)", state.levels());
            Some(state)
        }
    }
}

fn save_state(state: &KeyState) {
    match Persist::save(&state) {
        Err(e) => println!("Error: Could not save state {}", e),
        Ok(_) => println!("State saved"),
    }
}

fn boiler() {
    println!("NIP-41 Proto Zero");
    println!();
    println!("WARNING: This is a prototype implementation, use it only with test keys!");
    println!();
}

fn usage() {
    let progname = "nip41";
    println!("Usage:");
    println!();
    println!(
        "{} import       \t\t Import a BIP39 menmonic and create new state from it",
        progname
    );
    println!("{} generate     \t\t Generate a new key state", progname);
    println!(
        "{} [show]       \t\t Show current pubkey of the key state",
        progname
    );
    println!("{} inv       \t\t Invalidate current pubkey", progname);
    println!(
        "{} invprev   \t\t Display invalidation info from last invalidation, no change in state",
        progname
    );
    println!("{} verify    \t\t TODO", progname);
    println!();
}

fn do_generate() {
    let mgr = KeyManager::default();
    let state = mgr.generate_random().unwrap();
    save_state(&state);
}

fn pubkey_string(pk: &XOnlyPublicKey) -> String {
    format!("{}  ({})", pk.to_bech32().unwrap(), pk.to_string())
}

fn secret_key_string_short(sk: &SecretKey) -> String {
    let bech = sk.to_bech32().unwrap();
    let hex = hex::encode(sk.secret_bytes());
    format!(
        "{}..{}  ({}..{})",
        &bech[0..10],
        &bech[bech.len() - 6..bech.len()],
        &hex[0..10],
        &hex[hex.len() - 6..hex.len()]
    )
}

fn print_current(state: &KeyState) {
    println!(
        "Level: {}  (out of {})",
        state.current_level(),
        state.levels()
    );
    println!(
        "Current pubkey:     \t {}",
        pubkey_string(&state.current_pubkey())
    );
    println!(
        "Previous pubkey:    \t {}",
        match &state.previous_pubkey() {
            None => "None".to_string(),
            Some(k) => pubkey_string(k),
        }
    );
    println!(
        "Current secret key: \t {}",
        secret_key_string_short(&state.current_secret_key())
    );
}

fn do_show() {
    if let Some(state) = load_state() {
        print_current(&state);
    }
}

fn do_inv(commit: bool) {
    if let Some(mut state) = load_state() {
        print_current(&state);

        let inv_info = if commit {
            state.invalidate().unwrap()
        } else {
            match state.invalidate_prev() {
                Err(e) => {
                    println!("No invalidated key  ({e})");
                    return;
                }
                Ok(ii) => ii,
            }
        };
        println!("Invalidation info:");
        println!("Invalidated:       \t {}", pubkey_string(&inv_info.invalid));
        println!(
            "     hidden:       \t {}",
            pubkey_string(&inv_info.invalid_hid)
        );
        println!("        new:       \t {}", pubkey_string(&inv_info.new));
        if commit {
            print_current(&state);
        }

        // also do verify
        let mgr = KeyManager::default();
        let verify_result = mgr.verify(&inv_info.invalid, &inv_info.invalid_hid, &inv_info.new);
        println!("verify?         \t {:?}", verify_result);

        // obtain event
        let event = Nip41::build_invalidate_event_from_state(&mut state).unwrap();
        println!("Invalidation event: \n{}\n", event.as_json());

        // save
        if commit {
            save_state(&state);
        }
    }
}

fn main() {
    boiler();

    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        usage();
        do_show();
    } else {
        // there is an arg
        match args[1].as_str() {
            "import" => println!("TODO import"),
            "generate" => do_generate(),
            "show" => do_show(),
            "inv" => do_inv(true),
            "invprev" => do_inv(false),
            "verify" => println!("TODO verify"),
            &_ => usage(),
        }
    }
}
