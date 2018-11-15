extern crate exonum;
#[macro_use]
extern crate exonum_testkit;
extern crate private_currency;

use exonum::{crypto::CryptoHash, helpers::Height};
use exonum_testkit::{TestKit, TestKitBuilder};
use private_currency::{
    crypto::proofs::Opening,
    storage::{Event, Schema},
    transactions::SecretState,
    Service as Currency, INITIAL_BALANCE,
};

fn gen_wallet() -> SecretState {
    SecretState::new()
}

fn create_testkit() -> TestKit {
    TestKitBuilder::validator().with_service(Currency).create()
}

#[test]
fn create_2wallets_and_transfer_between_them() {
    let mut testkit = create_testkit();

    let mut alice_sec = gen_wallet();
    let bob_sec = gen_wallet();

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
    assert_eq!(alice_sec.to_public(), alice);

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
    assert_eq!(alice_sec.to_public(), alice);

    // Check that Bob will be notified about the payment
    let hashes = schema.unaccepted_payments(bob.public_key());
    assert_eq!(hashes, vec![transfer.hash()]);
}

#[test]
fn answering_payment() {
    const ROLLBACK_DELAY: u32 = 10;

    let mut testkit = create_testkit();

    let mut alice_sec = gen_wallet();
    let mut bob_sec = gen_wallet();
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
    assert!(schema.unaccepted_payments(bob_sec.public_key()).is_empty());
    // The transfer should no longer be in pending rollbacks.
    assert!(schema.rollback_transfers(rollback_height).is_empty());

    // Seeing the `Accept` transaction confirmed, Bob can safely modify his state.
    bob_sec.transfer(&transfer);
    assert_eq!(bob_sec.balance(), INITIAL_BALANCE + transfer_amount);
    let bob = schema.wallet(&bob_sec.public_key()).expect("Bob's wallet");
    assert!(bob_sec.corresponds_to(&bob));
}

#[test]
fn automatic_rollback() {
    const ROLLBACK_DELAY: u32 = 10;

    let mut testkit = create_testkit();

    let mut alice_sec = gen_wallet();
    let mut bob_sec = gen_wallet();
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
        .expect("Alice's wallet");
    assert!(alice_sec.corresponds_to(&alice));
}
