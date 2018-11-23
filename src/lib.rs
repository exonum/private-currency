// Copyright 2018 The Exonum Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Privacy-focused Exonum service. The service hides the amounts being
//! transferred among registered accounts (but not the identities of transacting accounts).
//!
//! # Implementation details
//!
//! The service uses [pure Rust implementation][bulletproofs-rs] for [Bulletproofs][bulletproofs],
//! a technique allowing to prove a range of a value hidden with the help of
//! the [Pedersen commitment scheme][pedersen]. Commitments are used
//! instead of values both in account details and in transfer transactions.
//!
//! ## Accounts
//!
//! The service uses account-based scheme similar to one used for ERC-20 tokens in Ethereum;
//! it is also used in simpler [demo cryptocurrency services for Exonum][demo].
//! Unlike other demos, each wallet contains a _commitment_ to the current
//! balance `Comm(bal; r)` instead of its plaintext value `bal`. Only the owner of the account
//! knows the opening to this commitment.
//!
//! ## Transfers
//!
//! Each transfer transaction contains a commitment to the transferred amount `C_a = Comm(a; r)`.
//! It is supplied with two range proofs:
//!
//! - The amount is non-negative: `a >= 0`
//! - The sender has sufficient balance on his account: `sender.bal >= a`
//!
//! The first proof is stateless, i.e., can be verified without consulting the blockchain state.
//! In order to verify the second proof, it's necessary to know the commitment `C_bal`
//! to the sender's current balance (which is stored in her wallet info). The proof is equivalent
//! to proving `C_bal - C_a` opens to a value in the allowed range.
//!
//! ## Transfer acceptance
//!
//! A natural question is how the receiver of the payment finds out about its amount `a`;
//! by design, it is impossible using only blockchain information. We solve this
//! by asymmetrically encrypting the opening to `C_a` - i.e., pair `(a, r)` -
//! with the help of `box` routine from `libsodium`, so it can only be decrypted by the
//! receiver and sender of the transfer. For simplicity, we convert Ed25519 keys used
//! to sign transactions to Curve25519 keys required for `box`; i.e., accounts are identified
//! by a single Ed25519 public key.
//!
//! A sender may maliciously encrypt garbage. Thus, we give the receiver a certain amount of time
//! after the transfer transaction is committed, to verify that she can decrypt it.
//! To signal successful verification, the receiver creates and sends a separate _acceptance_
//! transaction referencing the transfer.
//!
//! The _sender's balance_ decreases immediately after the transfer transaction is committed
//! (recall that it is stored as a commitment, so we perform arithmetic on commitments rather than
//! plaintext values). The _receiver's balance_ is not changed immediately; it is only increased
//! (again, using commitment arithmetic) only after her appropriate acceptance transaction
//! is committed.
//!
//! To prevent deadlocks, each transfer transaction specifies the timelock parameter
//! (in relative blockchain height, a la Bitcoin's `CSV` opcode). If this timelock expires
//! and the receiver of the transfer still hasn't accepted it,
//! the transfer is automatically refunded to the sender.
//!
//! ### Referencing past wallet states
//!
//! The scheme described above is *almost* practical, except for one thing:
//! the sender might not now her balance precisely at the moment of transfer!
//! Indeed, it might happen that the sender's stray accept transaction or a refund
//! are processed just before the sender's transfer (but after the transfer has been created,
//! signed and sent to the network). Hence, if we simply retrieve the sender's balance from
//! the blockchain state during transaction execution, there is a good chance it will differ
//! from the one the sender had in mind when creating the sufficient balance proof.
//!
//! In order to alleviate this problem, we allow the sender to specify what she thinks
//! is the length of her wallet history `history_len`. The proof of sufficient balance
//! is then checked against the balance commitment at this point in history.
//! For this scheme to be safe, we demand that `history_len - 1 >= last_send_index`,
//! where `last_send_index` is the index of the latest outgoing transfer in the sender's history
//! (we track `last_send_index` directly in the sender's account details).
//! If this inequality holds, it's safe to process the transfer; we know for sure that since
//! `last_send_index` the sender's balance can only increase (via incoming transfers
//! and/or refunds). Thus, if we subtract the transfer amount from the sender's *current* balance,
//! we still end up with non-negative balance.
//!
//! ## Limitations
//!
//! Even with heuristics described above, the scheme is limiting: before making a transfer,
//! the sender needs to know that there are no other unconfirmed outgoing transfers. This problem
//! could be solved with auto-increment counters *a la* Ethereum, or other means to order
//! transactions originating from the same user. This is outside the scope of this PoC.
//!
//! [bulletproofs]: https://eprint.iacr.org/2017/1066.pdf
//! [bulletproofs-rs]: https://doc.dalek.rs/bulletproofs/
//! [bulletproofs]: https://eprint.iacr.org/2017/1066.pdf
//! [pedersen]: https://en.wikipedia.org/wiki/Commitment_scheme
//! [demo]: https://github.com/exonum/exonum/tree/master/examples

#![deny(missing_docs, missing_debug_implementations)]

#[macro_use]
extern crate lazy_static;
extern crate byteorder;
#[macro_use]
extern crate exonum;
extern crate bulletproofs;
extern crate curve25519_dalek as curve25519;
extern crate exonum_sodiumoxide as sodiumoxide;
extern crate failure;
extern crate merlin;
extern crate rand;
#[macro_use]
extern crate failure_derive;
extern crate serde;
#[macro_use]
extern crate serde_derive;

use exonum::{
    api::ServiceApiBuilder,
    blockchain::{self as bc, ServiceContext, Transaction},
    crypto::Hash,
    encoding::Error as EncodingError,
    messages::RawMessage,
    storage::{Fork, Snapshot},
};

use std::ops::Range;

pub mod api;
pub mod crypto;
mod debug;
mod secrets;
pub mod storage;
pub mod transactions;
mod utils;

pub use api::Api;
use debug::DebuggerProbe;
pub use debug::{DebugEvent, Debugger, DebuggerOptions};
pub use secrets::{EncryptedData, SecretState, VerifiedTransfer};
pub use storage::{Schema, Wallet};
pub use transactions::CryptoTransactions as Transactions;

/// Human-readable service name.
pub const SERVICE_NAME: &str = "private_currency";
/// Service identifier.
pub const SERVICE_ID: u16 = 2_000;
/// Service configuration.
pub const CONFIG: Config = Config {
    initial_balance: 1_000_000,
    rollback_delay_bounds: 5..1_000,
    min_transfer_amount: 1,
};

/// Service configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Config {
    /// Initial amount of tokens for a new account.
    pub initial_balance: u64,
    /// Acceptable bounds on the `Transfer::rollback_delay()` parameter.
    pub rollback_delay_bounds: Range<u32>,
    /// Minimum acceptable transfer amount.
    pub min_transfer_amount: u64,
}

/// Privacy-preserving cryptocurrency service.
///
/// See crate documentation for more details.
#[derive(Debug, Default)]
pub struct Service {
    debugger_probe: Option<DebuggerProbe>,
}

impl Service {
    /// Creates a service with an attached debugger.
    ///
    /// The service created in this way has high associated performance penalty. Use for
    /// debugging only; otherwise, use `Service::default()`.
    pub fn debug(options: DebuggerOptions) -> (Self, Debugger) {
        let (probe, debugger) = DebuggerProbe::create_channel(16, options);
        let service = Service {
            debugger_probe: Some(probe),
        };
        (service, debugger)
    }
}

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
        Transactions::tx_from_raw(raw).map(|tx| tx.into())
    }

    fn before_commit(&self, fork: &mut Fork) {
        if let Some(ref probe) = self.debugger_probe {
            probe.on_before_commit(fork);
        }
        Schema::new(fork).do_rollback();
    }

    fn after_commit(&self, context: &ServiceContext) {
        if let Some(ref probe) = self.debugger_probe {
            probe.on_after_commit(context);
        }
    }

    fn wire_api(&self, builder: &mut ServiceApiBuilder) {
        builder
            .public_scope()
            .endpoint("v1/wallet", Api::wallet)
            .endpoint_mut("v1/transaction", Api::transaction);
    }
}
