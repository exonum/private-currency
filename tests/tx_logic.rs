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
    SecretState, Service as Currency, CONFIG,
};

use std::{collections::HashSet, iter::FromIterator};

const INITIAL_BALANCE: u64 = CONFIG.initial_balance;

fn create_testkit() -> TestKit {
    TestKitBuilder::validator()
        .with_service(Currency::default())
        .create()
}

#[test]
fn create_2wallets_and_transfer_between_them() {
    let mut testkit = create_testkit();

    let mut alice_sec = SecretState::with_random_keypair();
    let bob_sec = SecretState::with_random_keypair();

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

    let mut alice_sec = SecretState::with_random_keypair();
    let mut bob_sec = SecretState::with_random_keypair();
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
    let rollback_height = Height(testkit.height().0 + u64::from(ROLLBACK_DELAY));
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

    let mut alice_sec = SecretState::with_random_keypair();
    let mut bob_sec = SecretState::with_random_keypair();
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
    let rollback_height = Height(testkit.height().0 + u64::from(ROLLBACK_DELAY));
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
    let mut bob_sec = SecretState::with_random_keypair();
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
    let mut alice_sec = SecretState::with_random_keypair();
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
    let mut alice_sec = SecretState::with_random_keypair();
    let mut bob_sec = SecretState::with_random_keypair();
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

#[test]
fn concurrent_sends_from_same_wallet_fail() {
    let mut testkit = create_testkit();
    let mut alice_sec = SecretState::with_random_keypair();
    let mut bob_sec = SecretState::with_random_keypair();
    let bob_pk = *bob_sec.public_key();

    testkit
        .create_block_with_transactions(txvec![alice_sec.create_wallet(), bob_sec.create_wallet()]);
    alice_sec.initialize();
    bob_sec.initialize();

    let transfer = alice_sec.create_transfer(100, &bob_pk, 10);
    let other_transfer = alice_sec.create_transfer(200, &bob_pk, 10);
    assert_eq!(transfer.history_len(), other_transfer.history_len());

    let block = testkit.create_block_with_transactions(txvec![transfer.clone(), other_transfer]);
    assert!(block[0].status().is_ok());
    assert_eq!(
        block[1].status().unwrap_err().error_type(),
        TransactionErrorType::Code(Error::OutdatedHistory as u8)
    );

    alice_sec.transfer(&transfer);
    let schema = Schema::new(testkit.snapshot());
    // The first entry in the past balance cache should be deleted.
    assert!(schema.past_balance(alice_sec.public_key(), 0).is_none());
    assert_eq!(
        schema.past_balance(alice_sec.public_key(), 1).unwrap(),
        alice_sec.to_public().balance,
    );
}

#[test]
fn send_based_on_outdated_wallet_state_works() {
    let mut testkit = create_testkit();
    let mut alice_sec = SecretState::with_random_keypair();
    let mut bob_sec = SecretState::with_random_keypair();
    let alice_pk = *alice_sec.public_key();
    let bob_pk = *bob_sec.public_key();

    testkit
        .create_block_with_transactions(txvec![alice_sec.create_wallet(), bob_sec.create_wallet()]);
    alice_sec.initialize();
    bob_sec.initialize();

    let alice_transfer1 = alice_sec.create_transfer(100, &bob_pk, 10);
    testkit.create_block_with_transaction(alice_transfer1.clone());
    alice_sec.transfer(&alice_transfer1);
    let alice_transfer2 = alice_sec.create_transfer(100, &bob_pk, 10);
    testkit.create_block_with_transaction(alice_transfer2.clone());
    alice_sec.transfer(&alice_transfer2);

    let schema = Schema::new(testkit.snapshot());
    let alice_wallet = schema
        .wallet(alice_sec.public_key())
        .expect("Alice's wallet");
    assert_eq!(alice_wallet.info(), alice_sec.to_public());

    // Suppose Bob doesn't know about any of incoming transfers.
    let bob_transfer1 = bob_sec.create_transfer(150, &alice_pk, 10);
    let block = testkit.create_block_with_transaction(bob_transfer1.clone());
    assert!(block[0].status().is_ok());

    // ...Now, Bob partially synchronizes his state, receiving an event about `alice_transfer1`.
    let accept = bob_sec
        .verify_transfer(&alice_transfer1)
        .expect("verify_transfer")
        .accept;
    testkit.create_block_with_transaction(accept);

    // Bob fully synchronizes the state.
    bob_sec.transfer(&bob_transfer1);
    bob_sec.transfer(&alice_transfer1);
    let schema = Schema::new(testkit.snapshot());
    let bob_wallet = schema.wallet(&bob_pk).expect("Bob's wallet");
    assert_eq!(bob_wallet.info(), bob_sec.to_public());
}

#[test]
fn send_based_on_outdated_wallet_state_after_refund_works() {
    let mut testkit = create_testkit();
    let mut alice_sec = SecretState::with_random_keypair();
    let mut bob_sec = SecretState::with_random_keypair();
    let alice_pk = *alice_sec.public_key();
    let bob_pk = *bob_sec.public_key();

    testkit
        .create_block_with_transactions(txvec![alice_sec.create_wallet(), bob_sec.create_wallet()]);
    alice_sec.initialize();
    bob_sec.initialize();

    let alice_transfer1 = alice_sec.create_transfer(100, &bob_pk, 5);
    testkit.create_block_with_transaction(alice_transfer1.clone());
    alice_sec.transfer(&alice_transfer1);

    // Suppose Bob is offline, so he cannot accept the transfer.
    testkit.create_blocks_until(Height(10));
    // Now, Alice has the transfer refunded, but she doesn't know about it.

    let alice_transfer2 = alice_sec.create_transfer(200, &bob_pk, 5);
    let block = testkit.create_block_with_transaction(alice_transfer2.clone());
    assert!(block[0].status().is_ok());
    alice_sec.rollback(&alice_transfer1);
    alice_sec.transfer(&alice_transfer2);

    let accept = bob_sec
        .verify_transfer(&alice_transfer2)
        .expect("verify_transfer")
        .accept;
    testkit.create_block_with_transaction(accept);
    bob_sec.transfer(&alice_transfer2);

    let schema = Schema::new(testkit.snapshot());
    let alice_wallet = schema.wallet(&alice_pk).expect("Alice's wallet");
    assert_eq!(alice_wallet.info(), alice_sec.to_public());
    assert_eq!(alice_sec.balance(), INITIAL_BALANCE - 200);
    let bob_wallet = schema.wallet(&bob_pk).expect("Bob's wallet");
    assert_eq!(bob_wallet.info(), bob_sec.to_public());
    assert_eq!(bob_sec.balance(), INITIAL_BALANCE + 200);
}

#[test]
fn debugger() {
    use private_currency::{DebugEvent, DebuggerOptions};
    use std::{
        sync::{Arc, RwLock},
        thread,
    };

    let (currency, debugger) = Currency::debug(DebuggerOptions::default());
    let mut testkit = TestKitBuilder::validator().with_service(currency).create();

    let debug_events = Arc::new(RwLock::new(vec![]));
    let debug_events_ = debug_events.clone();
    let handle = thread::spawn(move || {
        for event in debugger {
            debug_events_.write().expect("debug_events").push(event);
        }
    });

    let mut alice_sec = SecretState::with_random_keypair();
    let mut bob_sec = SecretState::with_random_keypair();
    let alice_pk = *alice_sec.public_key();
    let bob_pk = *bob_sec.public_key();

    testkit
        .create_block_with_transactions(txvec![alice_sec.create_wallet(), bob_sec.create_wallet()]);
    alice_sec.initialize();
    bob_sec.initialize();

    let alice_transfer = alice_sec.create_transfer(100, &bob_pk, 5);
    let bob_transfer = bob_sec.create_transfer(200, &alice_pk, 7);
    testkit.create_block_with_transactions(txvec![alice_transfer.clone(), bob_transfer.clone(),]);
    testkit.create_blocks_until(Height(10)); // let both transfers expire

    let debug_events = debug_events.read().expect("read debug_events").clone();

    assert_eq!(
        debug_events,
        vec![
            DebugEvent::RolledBack {
                transfer: alice_transfer,
                height: Height(8)
            },
            DebugEvent::RolledBack {
                transfer: bob_transfer,
                height: Height(10)
            },
        ]
    );

    drop(testkit);
    handle.join().unwrap();
}
