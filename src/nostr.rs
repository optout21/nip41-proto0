/// Nostr-specific logic
///
use crate::keys::{Error, KeyState};
#[cfg(test)]
use nostr::prelude::UnsignedEvent;
use nostr::prelude::{Event, EventBuilder, Keys, Kind, Tag, TagKind, XOnlyPublicKey};
use nostr_sdk::prelude::{Client, Options};

pub struct Nip41 {}

impl Nip41 {
    pub fn invalidate_event_builder(
        invalid: XOnlyPublicKey,
        invalid_hid: XOnlyPublicKey,
    ) -> Result<EventBuilder, Error> {
        Ok(EventBuilder::new(
            Kind::Custom(13),
            "key invalidation".to_string(),
            &[
                Tag::PubKey(invalid, None),
                Tag::Generic(
                    TagKind::Custom(String::from("hidden-key")),
                    vec![invalid_hid.to_string()],
                ),
            ],
        ))
    }

    #[cfg(test)]
    pub fn build_invalidate_event_unsigned(
        invalid: XOnlyPublicKey,
        invalid_hid: XOnlyPublicKey,
        new_pk: XOnlyPublicKey,
    ) -> Result<UnsignedEvent, Error> {
        let eb = Self::invalidate_event_builder(invalid, invalid_hid)?;
        let event = eb.to_unsigned_event(new_pk);
        Ok(event)
    }

    // Build signed invalidation event, directly from state, for previous invalidation (so this should be called after comitting the invalidation).
    pub fn build_invalidate_event_from_state(state: &KeyState) -> Result<Event, Error> {
        let inv_info = state.invalidate_prev()?;
        let sk = state.current_secret_key();
        let eb = Self::invalidate_event_builder(inv_info.invalid, inv_info.invalid_hid)?;
        let event = eb.to_event(&Keys::new(sk))?;
        Ok(event)
    }

    async fn send_event(relay_client: &Client, event: Event) -> Result<(), Error> {
        let kind = event.kind;
        let id = relay_client.send_event(event).await?;
        println!("Event sent, kind {} id {}", kind.as_u32(), id);
        Ok(())
    }

    pub async fn send_event_to_relay(relay: &str, event: Event) -> Result<(), Error> {
        let app_keys = Keys::generate();
        let opts = Options::new().wait_for_send(true);
        let relay_client = Client::new_with_opts(&app_keys, opts);
        relay_client.add_relay(relay.to_string(), None).await?;
        relay_client.connect().await;
        println!("Connected to relay {relay}");
        Self::send_event(&relay_client, event).await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::Nip41;
    use crate::keys::KeyManager;
    use ::nostr::prelude::{EventId, Timestamp};

    const MNEMO1: &str = "oil oil oil oil oil oil oil oil oil oil oil oil";

    #[test]
    fn test_build_invalidate_event() {
        let km = KeyManager::default();
        let mut state = km.generate_from_mnemonic(MNEMO1).unwrap();
        let inv_info = state.invalidate().unwrap();

        let mut event = Nip41::build_invalidate_event_unsigned(
            inv_info.invalid,
            inv_info.invalid_hid,
            inv_info.new,
        )
        .unwrap();
        // set created_at and id to const for comparison, recompute Id
        event.created_at = Timestamp::from(1680359581);
        event.id = EventId::new(
            &event.pubkey,
            event.created_at,
            &event.kind,
            &event.tags,
            &event.content,
        );

        let event_json = event.as_json();
        assert_eq!(event_json, "{\"content\":\"key invalidation\",\"created_at\":1680359581,\"id\":\"45b635e767caf77a7086c1dc60b4db22c35194bc1221f25f67749d70495dc90c\",\"kind\":13,\"pubkey\":\"cccffb5cf8a7e494481c585ba02aeb2b88fa0608e6423f4f45a1f2724aef0f9c\",\"tags\":[[\"p\",\"2d051acc76e2102d85ed666bc440f44b6c0a02359c486eb8a714bdd480b89855\"],[\"hidden-key\",\"624dcd67b36c9c7e24397b817b8c7501f42d53def3070d6a4c354bf576899919\"]]}");
    }
}
