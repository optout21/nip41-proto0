mod keys;
mod nostr;
mod persist;

use crate::keys::{Error, KeyManager, KeyState};
use crate::nostr::Nip41;
use crate::persist::Persist;
use ::nostr::prelude::{FromPkStr, Keys, ToBech32};
use secp256k1::{SecretKey, XOnlyPublicKey};
use std::env;
use std::io::{BufRead, Write};
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
        "{} import       \t Import a BIP39 menmonic and create new state from it",
        progname
    );
    println!("{} generate     \t Generate a new key state", progname);
    println!(
        "{} [show]       \t Show current pubkey of the key state",
        progname
    );
    println!("{} inv       \t Invalidate current pubkey", progname);
    println!(
        "{} invprev   \t Display invalidation info from last invalidation, no change in state",
        progname
    );
    println!("{} verify <invalid> <invalid_hid> <new>  \t Verify key invalidation; 3 pubkeys must be supplied (npub or hex)", progname);
    println!(
        "{} invsend <relay>  \t Send invalidation event to relay, first do invalidation (with 'inv')",
        progname
    );
    println!();
}

fn do_generate() {
    let mgr = KeyManager::default();
    let state = mgr.generate_random().unwrap();
    save_state(&state);
    print_current(&state);
}

fn do_import() {
    loop {
        // ask for mnemonic interactively
        print!("Enter mnemonic (12-24 words): ");
        std::io::stdout().flush().unwrap(); // Without flushing, the `>` doesn't print
        let stdin = std::io::stdin();
        let mut line_reader = stdin.lock().lines();
        match line_reader.next() {
            None => {}
            Some(l) => match l {
                Err(_) => {}
                Ok(l) => {
                    let mgr = KeyManager::default();
                    match mgr.generate_from_mnemonic(&l) {
                        Err(e) => println!("Error: Could not generate from mnemonic; {e}"),
                        Ok(state) => {
                            save_state(&state);
                            print_current(&state);
                            break;
                        }
                    }
                }
            },
        };
    }
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
    } else {
        println!("Error: Could not load saved state");
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
    } else {
        println!("Error: Could not load saved state");
    }
}

fn do_verify_int(
    invalid_str: &str,
    invalid_hid_str: &str,
    new_pk_str: &str,
) -> Result<bool, Error> {
    let invalid = Keys::from_pk_str(invalid_str)?.public_key();
    let invalid_hid = Keys::from_pk_str(invalid_hid_str)?.public_key();
    let new_pk = Keys::from_pk_str(new_pk_str)?.public_key();
    println!("Invalid vis     \t {}", pubkey_string(&invalid));
    println!("Invalid hid     \t {}", pubkey_string(&invalid_hid));
    println!("New vis         \t {}", pubkey_string(&new_pk));
    Ok(KeyManager::default().verify(&invalid, &invalid_hid, &new_pk))
}

fn do_verify(invalid: &str, invalid_hid: &str, new_pk: &str) {
    match do_verify_int(invalid, invalid_hid, new_pk) {
        Err(e) => println!("Error: {e}"),
        Ok(res) => println!("Verification result:  {res}"),
    }
}

async fn do_invsend_int(state: &KeyState, relay: &str) -> Result<(), Error> {
    let event = Nip41::build_invalidate_event_from_state(&state)?;
    println!("Invalidation event: {}", event.as_json());
    Nip41::send_event_to_relay(relay, event).await?;
    Ok(())
}

async fn do_invsend(relay: &str) {
    if let Some(state) = load_state() {
        println!("Relay: {relay}");
        match do_invsend_int(&state, relay).await {
            Err(e) => println!("Error: Could not send event; {e}"),
            Ok(_) => {}
        }
    } else {
        println!("Error: Could not load saved state");
    }
}

#[tokio::main]
async fn main() {
    boiler();

    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        usage();
        do_show();
    } else {
        // there is an arg
        match args[1].as_str() {
            "import" => do_import(),
            "generate" => do_generate(),
            "show" => do_show(),
            "inv" => do_inv(true),
            "invprev" => do_inv(false),
            "verify" => {
                if args.len() < 2 + 3 {
                    println!("Error: missing arguments, 3 needed");
                    usage()
                } else {
                    do_verify(&args[2], &args[3], &args[4]);
                }
            }
            "invsend" => {
                if args.len() < 2 + 1 {
                    println!("Error: missing relay argument");
                    usage()
                } else {
                    do_invsend(&args[2]).await;
                }
            }
            &_ => usage(),
        }
    }
}
