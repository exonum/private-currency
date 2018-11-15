#[macro_use]
extern crate lazy_static;
extern crate byteorder;
#[macro_use]
extern crate exonum;
extern crate bulletproofs;
extern crate curve25519_dalek as curve25519;
extern crate exonum_sodiumoxide as sodiumoxide;
extern crate merlin;
extern crate rand;
extern crate serde;
#[macro_use]
extern crate serde_derive;

use exonum::{
    api::ServiceApiBuilder,
    blockchain::{self as bc, Transaction},
    crypto::Hash,
    encoding::Error as EncodingError,
    messages::RawMessage,
    storage::{Fork, Snapshot},
};

use std::ops::Range;

pub mod api;
pub mod crypto;
pub mod storage;
pub mod transactions;

use api::Api;
use storage::Schema;
use transactions::CryptoTransactions;

pub const SERVICE_NAME: &str = "private_currency";
pub const SERVICE_ID: u16 = 2_000;

/// Initial amount of tokens for a new account.
pub const INITIAL_BALANCE: u64 = 1_000_000;
/// Acceptable bounds on the `Transfer::rollback_delay()` parameter.
pub const ROLLBACK_DELAY_BOUNDS: Range<u32> = 5..1_000;

pub struct Service;

impl bc::Service for Service {
    fn service_id(&self) -> u16 {
        SERVICE_ID
    }

    fn service_name(&self) -> &str {
        SERVICE_NAME
    }

    fn state_hash(&self, snapshot: &dyn Snapshot) -> Vec<Hash> {
        Schema::new(snapshot).state_hash()
    }

    fn tx_from_raw(&self, raw: RawMessage) -> Result<Box<Transaction>, EncodingError> {
        use bc::TransactionSet;
        CryptoTransactions::tx_from_raw(raw).map(|tx| tx.into())
    }

    fn before_commit(&self, fork: &mut Fork) {
        Schema::new(fork).do_rollback();
    }

    fn wire_api(&self, builder: &mut ServiceApiBuilder) {
        builder
            .public_scope()
            .endpoint("v1/wallet", Api::wallet)
            .endpoint("v1/unaccepted", Api::unaccepted_transfers)
            .endpoint_mut("v1/transaction", Api::transaction);
    }
}
