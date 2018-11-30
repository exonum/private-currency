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

#![feature(external_doc)]
#![deny(missing_docs, missing_debug_implementations)]
#![doc(html_favicon_url = "https://exonum.com/favicon.ico")]

//! Privacy-focused Exonum service. The service hides the amounts being
//! transferred among registered accounts (but not the identities of transacting accounts).
//!
#![doc(include = "../docs/implementation.md")]

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
