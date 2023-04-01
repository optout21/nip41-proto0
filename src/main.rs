mod keys;
mod persist;

use crate::keys::{KeyManager, KeyState};
use crate::persist::Persist;
use std::env;

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
    println!("NIP-41 Proto 0");
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
    println!("{} invdry    \t\t Dry-run invalidate, display as if invalidating current pubkey without comitting to it", progname);
    println!("{} verify    \t\t TODO", progname);
    println!();
}

fn do_generate() {
    let mgr = KeyManager::default();
    let state = mgr.generate_random().unwrap();
    save_state(&state);
}

fn print_current(state: &KeyState) {
    println!(
        "Level: {}  (out of {})",
        state.current_level(),
        state.levels()
    );
    println!(
        "Current pubkey:     \t {:?}",
        state.current_visible_pubkey().unwrap()
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
        let (a, ah, b, _a_vec) = state.invalidate(commit).unwrap();
        println!("Invalidated:     \t {:?}", a);
        println!("     hidden:     \t {:?}", ah);
        println!("        new:     \t {:?}", b);
        print_current(&state);

        // also do verify
        let mgr = KeyManager::default();
        let verify_result = mgr.verify(&a, &ah, &b);
        println!("verify?  \t {:?}", verify_result);

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
            "invdry" => do_inv(false),
            "verify" => println!("TODO verify"),
            &_ => usage(),
        }
    }
}
