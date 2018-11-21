//! Tests for transaction logic of the service.

extern crate exonum;
#[macro_use]
extern crate exonum_testkit;
extern crate private_currency;

use exonum::{
    blockchain::TransactionErrorType,
    crypto::{self, CryptoHash, Hash},
    helpers::Height,
};
use exonum_testkit::{TestKit, TestKitBuilder};
use private_currency::{
    crypto::Opening,
    storage::{Event, Schema},
    transactions::{Accept, Error},
    SecretState, Service as Currency, INITIAL_BALANCE,
};

use std::{collections::HashSet, iter::FromIterator};

fn create_testkit() -> TestKit {
    TestKitBuilder::validator().with_service(Currency).create()
}

#[test]
fn create_2wallets_and_transfer_between_them() {
    let mut testkit = create_testkit();

    let mut alice_sec = SecretState::new();
    let bob_sec = SecretState::new();

    let create_wallet_for_alice = alice_sec.create_wallet();
    testkit.create_block_with_transactions(txvec![
        create_wallet_for_alice.clone(),
        bob_sec.create_wallet(),
    ]);

    let schema = Schema::new(testkit.snapshot());
    let alice = schema
        .wallet(alice_sec.public_key())
        .expect("alice's wallet");
    assert!(
        alice
            .balance()
            .verify(&Opening::with_no_blinding(INITIAL_BALANCE))
    );
    assert!(schema.wallet(bob_sec.public_key()).is_some());

    // Check that `CreateWallet` transactions are properly recorded in wallet history.
    assert_eq!(
        schema.history(alice.public_key()),
        vec![Event::create_wallet(&create_wallet_for_alice.hash())]
    );
    alice_sec.initialize();
    assert_eq!(alice_sec.to_public(), alice.info());

    let transfer_amount = INITIAL_BALANCE / 3;
    let transfer = alice_sec.create_transfer(transfer_amount, &bob_sec.public_key(), 10);
    testkit.create_block_with_transaction(transfer.clone());

    let schema = Schema::new(testkit.snapshot());
    // The Alice's balance should change immediately.
    let alice = schema
        .wallet(alice_sec.public_key())
        .expect("Alice's wallet");
    assert!(
        !alice
            .balance()
            .verify(&Opening::with_no_blinding(INITIAL_BALANCE))
    );
    // Bob's balance, OTOH, should be intact.
    let bob = schema.wallet(bob_sec.public_key()).expect("Bob's wallet");
    assert!(
        bob.balance()
            .verify(&Opening::with_no_blinding(INITIAL_BALANCE))
    );

    assert_eq!(
        schema.history(alice.public_key()),
        vec![
            Event::create_wallet(&create_wallet_for_alice.hash()),
            Event::transfer(&transfer.hash()),
        ]
    );
    alice_sec.transfer(&transfer);
    assert_eq!(alice_sec.to_public(), alice.info());

    // Check that Bob will be notified about the payment
    let hashes = schema.unaccepted_transfers(bob.public_key());
    assert_eq!(hashes, HashSet::from_iter(vec![transfer.hash()]));
}

#[test]
fn answering_payment() {
    const ROLLBACK_DELAY: u32 = 10;

    let mut testkit = create_testkit();

    let mut alice_sec = SecretState::new();
    let mut bob_sec = SecretState::new();
    alice_sec.initialize();
    bob_sec.initialize();
    let transfer_amount = INITIAL_BALANCE / 3;
    let transfer =
        alice_sec.create_transfer(transfer_amount, &bob_sec.public_key(), ROLLBACK_DELAY);

    let block = testkit.create_block_with_transactions(txvec![
        alice_sec.create_wallet(),
        bob_sec.create_wallet(),
        transfer.clone(),
    ]);
    assert!(block.iter().all(|tx| tx.status().is_ok()));
    // Check that the transfer is in pending rollbacks at appropriate height.
    let schema = Schema::new(testkit.snapshot());
    let rollback_height = Height(testkit.height().0 + ROLLBACK_DELAY as u64);
    assert_eq!(
        schema.rollback_transfers(rollback_height),
        vec![transfer.hash()]
    );

    // Bob verifies the incoming transfer (successfully).
    let verified = bob_sec.verify_transfer(&transfer).expect("verify_transfer");
    assert_eq!(verified.value(), transfer_amount);
    // Bob sends `Accept` in response.
    testkit.create_block_with_transaction(verified.accept);

    let schema = Schema::new(testkit.snapshot());
    let bob_history = schema.history(bob_sec.public_key());
    assert_eq!(bob_history.len(), 2);
    assert_eq!(bob_history[1], Event::transfer(&transfer.hash()));
    assert!(schema.unaccepted_transfers(bob_sec.public_key()).is_empty());
    // The transfer should no longer be in pending rollbacks.
    assert!(schema.rollback_transfers(rollback_height).is_empty());

    // Seeing the `Accept` transaction confirmed, Bob can safely modify his state.
    bob_sec.transfer(&transfer);
    assert_eq!(bob_sec.balance(), INITIAL_BALANCE + transfer_amount);
    let bob = schema
        .wallet(&bob_sec.public_key())
        .expect("Bob's wallet")
        .info();
    assert!(bob_sec.corresponds_to(&bob));
}

#[test]
fn automatic_rollback() {
    const ROLLBACK_DELAY: u32 = 10;

    let mut testkit = create_testkit();

    let mut alice_sec = SecretState::new();
    let mut bob_sec = SecretState::new();
    alice_sec.initialize();
    bob_sec.initialize();
    let transfer_amount = INITIAL_BALANCE / 3;
    let transfer =
        alice_sec.create_transfer(transfer_amount, &bob_sec.public_key(), ROLLBACK_DELAY);

    testkit.create_block_with_transactions(txvec![
        alice_sec.create_wallet(),
        bob_sec.create_wallet(),
        transfer.clone(),
    ]);
    alice_sec.transfer(&transfer);
    let rollback_height = Height(testkit.height().0 + ROLLBACK_DELAY as u64);
    testkit.create_blocks_until(rollback_height.next().next());

    let schema = Schema::new(testkit.snapshot());
    let bob_history = schema.history(bob_sec.public_key());
    assert_eq!(bob_history.len(), 1);
    let alice_history = schema.history(alice_sec.public_key());
    assert_eq!(alice_history.len(), 3);
    assert_eq!(alice_history[2], Event::rollback(&transfer.hash()));

    assert!(schema.rollback_transfers(rollback_height).is_empty());

    // Seeing the rollback, Alice updates its state.
    alice_sec.rollback(&transfer);
    assert_eq!(alice_sec.balance(), INITIAL_BALANCE);
    let alice = schema
        .wallet(alice_sec.public_key())
        .expect("Alice's wallet")
        .info();
    assert!(alice_sec.corresponds_to(&alice));
}

#[test]
fn unauthorized_accept() {
    let mut testkit = create_testkit();

    let (pk, sk) = crypto::gen_keypair();
    let mut alice_sec = SecretState::from_keypair(pk, sk.clone());
    let mut bob_sec = SecretState::new();
    alice_sec.initialize();
    bob_sec.initialize();
    let transfer_amount = INITIAL_BALANCE / 3;
    let transfer = alice_sec.create_transfer(transfer_amount, &bob_sec.public_key(), 10);

    testkit.create_block_with_transactions(txvec![
        alice_sec.create_wallet(),
        bob_sec.create_wallet(),
        transfer.clone(),
    ]);

    let accept = Accept::new(&pk, &transfer.hash(), &sk);
    let block = testkit.create_block_with_transaction(accept);
    assert_eq!(
        block[0].status().unwrap_err().error_type(),
        TransactionErrorType::Code(Error::UnauthorizedAccept as u8)
    );
    let schema = Schema::new(testkit.snapshot());
    let bob_wallet = schema.wallet(bob_sec.public_key()).expect("Bob's wallet");
    assert!(
        bob_wallet
            .balance()
            .verify(&Opening::with_no_blinding(INITIAL_BALANCE))
    );
    assert!(
        schema
            .unaccepted_transfers(bob_sec.public_key())
            .contains(&transfer.hash())
    );
}

fn accept_several_transfers<F>(accept_fn: F)
where
    F: FnOnce(&mut TestKit, &Accept, &Accept),
{
    let mut testkit = create_testkit();
    let mut alice_sec = SecretState::new();
    let mut bob_sec = SecretState::new();
    let mut carol_sec = SecretState::new();

    testkit.create_block_with_transactions(txvec![
        alice_sec.create_wallet(),
        bob_sec.create_wallet(),
        carol_sec.create_wallet(),
    ]);
    alice_sec.initialize();
    bob_sec.initialize();
    carol_sec.initialize();

    let transfer_from_alice = alice_sec.create_transfer(1_000, carol_sec.public_key(), 10);
    let transfer_from_bob = bob_sec.create_transfer(2_000, carol_sec.public_key(), 15);

    let block = testkit.create_block_with_transactions(txvec![
        transfer_from_alice.clone(),
        transfer_from_bob.clone(),
    ]);
    assert!(block.iter().all(|tx| tx.status().is_ok()));

    let schema = Schema::new(testkit.snapshot());
    assert_eq!(
        schema.unaccepted_transfers(&carol_sec.public_key()),
        HashSet::from_iter(vec![transfer_from_alice.hash(), transfer_from_bob.hash()])
    );

    let accept_alice = carol_sec
        .verify_transfer(&transfer_from_alice)
        .expect("accept_alice")
        .accept;
    let accept_bob = carol_sec
        .verify_transfer(&transfer_from_bob)
        .expect("accept_bob")
        .accept;

    accept_fn(&mut testkit, &accept_alice, &accept_bob);

    let schema = Schema::new(testkit.snapshot());
    assert!(
        schema
            .unaccepted_transfers(&carol_sec.public_key())
            .is_empty()
    );
    let history = schema.history(&carol_sec.public_key());
    assert_eq!(history.len(), 3);

    let expected_events = vec![
        Event::transfer(&transfer_from_alice.hash()),
        Event::transfer(&transfer_from_bob.hash()),
    ];
    let expected_events: HashSet<&Event> = HashSet::from_iter(&expected_events);
    assert_eq!(HashSet::from_iter(&history[1..]), expected_events);

    carol_sec.transfer(&transfer_from_alice);
    carol_sec.transfer(&transfer_from_bob);
    let carol_wallet = schema
        .wallet(&carol_sec.public_key())
        .expect("Carol's wallet")
        .info();
    assert_eq!(carol_sec.balance(), INITIAL_BALANCE + 3_000);
    assert!(carol_sec.corresponds_to(&carol_wallet));
}

#[test]
fn accept_several_transfers_in_single_block() {
    accept_several_transfers(|testkit, accept_alice, accept_bob| {
        let block = testkit
            .create_block_with_transactions(txvec![accept_alice.clone(), accept_bob.clone()]);
        assert!(block.iter().all(|tx| tx.status().is_ok()));
    });
}

#[test]
fn accept_several_transfers_in_single_block_unordered() {
    accept_several_transfers(|testkit, accept_alice, accept_bob| {
        let block = testkit
            .create_block_with_transactions(txvec![accept_bob.clone(), accept_alice.clone()]);
        assert!(block.iter().all(|tx| tx.status().is_ok()));
    });
}

#[test]
fn accept_several_transfers_in_multiple_blocks() {
    accept_several_transfers(|testkit, accept_alice, accept_bob| {
        let block = testkit.create_block_with_transaction(accept_alice.to_owned());
        assert!(block.iter().all(|tx| tx.status().is_ok()));
        testkit.create_block();
        let block = testkit.create_block_with_transaction(accept_bob.to_owned());
        assert!(block.iter().all(|tx| tx.status().is_ok()));
    });
}

#[test]
fn accept_several_transfers_in_multiple_blocks_unordered() {
    accept_several_transfers(|testkit, accept_alice, accept_bob| {
        let block = testkit.create_block_with_transaction(accept_bob.to_owned());
        assert!(block.iter().all(|tx| tx.status().is_ok()));
        testkit.create_block();
        testkit.create_block();
        let block = testkit.create_block_with_transaction(accept_alice.to_owned());
        assert!(block.iter().all(|tx| tx.status().is_ok()));
    });
}

#[test]
fn expired_transfers_are_removed_from_indexes() {
    let mut testkit = create_testkit();
    let mut alice_sec = SecretState::new();
    let mut bob_sec = SecretState::new();
    let bob_pk = *bob_sec.public_key();

    testkit
        .create_block_with_transactions(txvec![alice_sec.create_wallet(), bob_sec.create_wallet()]);
    alice_sec.initialize();
    bob_sec.initialize();

    let transfer = alice_sec.create_transfer(1_000, &bob_pk, 5);
    testkit.create_block_with_transaction(transfer.clone());
    let schema = Schema::new(testkit.snapshot());
    assert_eq!(schema.rollback_transfers(Height(7)).len(), 1);

    // Wait until the transfer is rolled back.
    testkit.create_blocks_until(Height(10));

    let schema = Schema::new(testkit.snapshot());
    assert_eq!(schema.history(&bob_pk).len(), 1);
    assert!(schema.unaccepted_transfers(&bob_pk).is_empty());
    assert!(schema.rollback_transfers(Height(6)).is_empty());
    // As there are not unaccepted transfers now, the corresponding field in the Bob's wallet
    // should be zeroed.
    let bob_wallet = schema.wallet(&bob_pk).expect("Bob's wallet");
    assert_eq!(*bob_wallet.unaccepted_transfers_hash(), Hash::zero());
}
