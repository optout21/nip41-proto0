use crate::keys::KeyManager;

mod keys;

fn main() {
    println!("NIP-41 Proto 0");

    println!("Generating new state...");
    let mgr = KeyManager::default();
    let mut state = mgr.generate_random().unwrap();

    println!("Levels: {}", state.levels());
    println!(
        "Current secret key: \t {:?}",
        state.current_visible_secret_key().unwrap()
    );
    println!(
        "Current pubkey:     \t {:?}",
        state.current_visible_pubkey().unwrap()
    );

    let (a, ah, b) = state.invalidate().unwrap();
    println!("Invalidated:     \t {:?}", a);
    println!("     hidden:     \t {:?}", ah);
    println!("         to:     \t {:?}", b);
    println!(
        "Current pubkey:     \t {:?}",
        state.current_visible_pubkey().unwrap()
    );

    let verify_result = mgr.verify(&a, &ah, &b);
    println!("verify?  \t {:?}", verify_result);
}
