//! Tests for HTTP API of the service.

extern crate exonum;
#[macro_use]
extern crate exonum_testkit;
extern crate private_currency;

use exonum::crypto::{CryptoHash, PublicKey};
use exonum_testkit::{ApiKind, TestKit, TestKitBuilder};

use std::{collections::HashSet, iter::FromIterator};

use private_currency::{
    api::{CheckedWalletProof, FullEvent, TrustAnchor, WalletProof, WalletQuery},
    SecretState, Service as Currency,
};

fn create_testkit() -> TestKit {
    TestKitBuilder::validator()
        .with_service(Currency::default())
        .create()
}

fn wallet(testkit: &TestKit, key: PublicKey, start_history_at: u64) -> CheckedWalletProof {
    let trust_anchor = TrustAnchor::new(
        testkit
            .network()
            .validators()
            .iter()
            .map(|node| node.public_keys().consensus_key),
    );

    let query = WalletQuery {
        key,
        start_history_at,
    };
    let wallet_proof: WalletProof = testkit
        .api()
        .public(ApiKind::Service("private_currency"))
        .query(&query)
        .get("v1/wallet")
        .unwrap();
    wallet_proof.check(&trust_anchor, &query).unwrap()
}

#[test]
fn wallet_api() {
    let mut testkit = create_testkit();

    let mut alice_sec = SecretState::with_random_keypair();
    let alice_pk = *alice_sec.public_key();
    let mut bob_sec = SecretState::with_random_keypair();
    let mut carol_sec = SecretState::with_random_keypair();

    testkit.create_block_with_transactions(txvec![
        alice_sec.create_wallet(),
        bob_sec.create_wallet(),
        carol_sec.create_wallet(),
    ]);
    alice_sec.initialize();
    bob_sec.initialize();
    carol_sec.initialize();

    let response = wallet(&testkit, alice_pk, 0);
    assert_eq!(
        response.wallet.as_ref().expect("Alice's wallet").info(),
        alice_sec.to_public()
    );
    assert_eq!(response.history.len(), 1);
    assert!(response.unaccepted_transfers.is_empty());

    // Send a couple of transfers from Bob and Carol.
    let transfer_from_bob = bob_sec.create_transfer(1_000, &alice_pk, 10);
    let transfer_from_carol = carol_sec.create_transfer(1_500, &alice_pk, 10);
    testkit.create_block_with_transactions(txvec![
        transfer_from_bob.clone(),
        transfer_from_carol.clone(),
    ]);

    let response = wallet(&testkit, alice_pk, 1);
    assert_eq!(
        response.wallet.as_ref().expect("Alice's wallet").info(),
        alice_sec.to_public()
    );
    assert!(response.history.is_empty());
    assert_eq!(
        HashSet::from_iter(response.unaccepted_transfers.iter().map(CryptoHash::hash)),
        HashSet::<_>::from_iter(vec![transfer_from_bob.hash(), transfer_from_carol.hash()]),
    );

    // Accept one of transfers.
    let accept = alice_sec
        .verify_transfer(&transfer_from_bob)
        .expect("verified transfer")
        .accept;
    testkit.create_block_with_transaction(accept.clone());

    let response = wallet(&testkit, alice_pk, 1);
    assert_eq!(response.history.len(), 1);
    assert_eq!(
        response.history[0],
        FullEvent::Transfer(transfer_from_bob.clone())
    );
    assert_eq!(response.unaccepted_transfers.len(), 1);
    assert_eq!(response.unaccepted_transfers, vec![transfer_from_carol]);
    alice_sec.transfer(&transfer_from_bob);
    assert_eq!(
        response.wallet.as_ref().expect("Alice's wallet").info(),
        alice_sec.to_public()
    );
}
