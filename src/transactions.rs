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

//! Transaction logic of the service.

use exonum::{
    blockchain::{ExecutionError, Transaction},
    crypto::{Hash, PublicKey},
    messages::Message,
    storage::Fork,
};

use super::{CONFIG, SERVICE_ID};
use crypto::{Commitment, SimpleRangeProof};
use secrets::EncryptedData;
use storage::{maybe_transfer, Schema};

lazy_static! {
    static ref MIN_TRANSFER_COMMITMENT: Commitment =
        Commitment::with_no_blinding(CONFIG.min_transfer_amount);
}

transactions! {
    /// Transactions accepted by the service.
    pub CryptoTransactions {
        const SERVICE_ID = SERVICE_ID;

        /// Transaction for creating a new wallet.
        ///
        /// # Notes
        ///
        /// This transaction specifies only the Ed25519 verification key used to check
        /// digital signatures of transactions authored by the wallet owner. The public encryption
        /// key of the wallet owner is deterministically derived from the verification key.
        struct CreateWallet {
            /// Ed25519 key for the wallet.
            key: &PublicKey,
        }

        /// Transfer from one wallet to another wallet.
        ///
        /// See [crate docs](crate) for explanation about fields and workflow of `Transfer`
        /// transactions.
        struct Transfer {
            /// Ed25519 public key of the sender. The transaction must be signed with the
            /// corresponding secret key.
            from: &PublicKey,

            /// Ed25519 public key of the receiver.
            to: &PublicKey,

            /// Relative delay (measured in block height) to wait for transfer acceptance from the
            /// receiver. The delay is counted from the height of a block containing
            /// this `Transfer`.
            ///
            /// If the transaction is not [`Accept`]ed by the receiver when the delay expires,
            /// the transfer is automatically rolled back.
            ///
            /// [`Accept`]: struct.Accept.html
            rollback_delay: u32,

            /// Length of the wallet history as perceived by the wallet sender.
            ///
            /// This value may be lesser than the real wallet history length. What’s important
            /// is that `history_len` must not be less then [`last_send_index`] of the sender’s
            /// wallet (i.e., the sender must be aware of all her outgoing transfers).
            /// If `history_len` is less, the transfer is considered invalid.
            ///
            /// [`last_send_index`]: ::storage::Wallet::last_send_index()
            history_len: u64,

            /// Commitment to the transferred amount.
            amount: Commitment,

            /// Proof that `amount` is positive.
            amount_proof: SimpleRangeProof,

            /// Proof that the sender’s balance is sufficient relative to `amount`.
            sufficient_balance_proof: SimpleRangeProof,

            /// Encryption of the opening for `amount`.
            encrypted_data: EncryptedData,
        }

        /// Transaction to accept an incoming transfer.
        struct Accept {
            /// Public key of the receiver of the transfer.
            receiver: &PublicKey,
            /// Hash of the transfer transaction.
            transfer_id: &Hash,
        }
    }
}

impl Transaction for CreateWallet {
    fn verify(&self) -> bool {
        self.verify_signature(self.key())
    }

    fn execute(&self, fork: &mut Fork) -> Result<(), ExecutionError> {
        let mut schema = Schema::new(fork);
        schema.create_wallet(self.key(), self)?;
        Ok(())
    }
}

impl Transfer {
    /// Performs stateless verification of the transfer operation.
    pub(crate) fn verify_stateless(&self) -> bool {
        self.amount_proof()
            .verify(&(&self.amount() - &MIN_TRANSFER_COMMITMENT))
    }

    pub(crate) fn verify_stateful(&self, balance: &Commitment) -> bool {
        let remaining_balance = balance - &self.amount();
        self.sufficient_balance_proof().verify(&remaining_balance)
    }
}

impl Transaction for Transfer {
    fn verify(&self) -> bool {
        if CONFIG.rollback_delay_bounds.start > self.rollback_delay()
            || CONFIG.rollback_delay_bounds.end <= self.rollback_delay()
        {
            return false;
        }
        self.history_len() > 0
            && self.from() != self.to()
            && self.verify_signature(self.from())
            && self.verify_stateless()
    }

    fn execute(&self, fork: &mut Fork) -> Result<(), ExecutionError> {
        let (sender, receiver) = {
            let schema = Schema::new(fork.as_ref());
            (schema.wallet(self.from()), schema.wallet(self.to()))
        };
        let sender = sender.ok_or(Error::UnregisteredSender)?;
        let receiver = receiver.ok_or(Error::UnregisteredReceiver)?;

        if sender.last_send_index() + 1 > self.history_len() {
            Err(Error::OutdatedHistory)?;
        }
        let past_balance = {
            let schema = Schema::new(fork.as_ref());
            schema
                .past_balance(sender.public_key(), self.history_len() - 1)
                .ok_or_else(|| {
                    println!(
                        "!!! missing ref: {} / {} / len={}",
                        self.history_len() - 1,
                        sender.last_send_index(),
                        sender.history_len()
                    );
                    Error::InvalidHistoryRef
                })?
        };
        if !self.verify_stateful(&past_balance) {
            Err(Error::IncorrectProof)?;
        }

        let mut schema = Schema::new(fork);
        schema.update_sender(&sender, &self.amount(), self);
        schema.add_unaccepted_payment(&receiver, self);

        Ok(())
    }
}

impl Transaction for Accept {
    fn verify(&self) -> bool {
        self.verify_signature(self.receiver())
    }

    fn execute(&self, fork: &mut Fork) -> Result<(), ExecutionError> {
        let transfer = maybe_transfer(&fork, self.transfer_id()).ok_or(Error::UnknownTransfer)?;
        if transfer.to() != self.receiver() {
            Err(Error::UnauthorizedAccept)?;
        }

        let mut schema = Schema::new(fork);
        schema.accept_payment(&transfer, self.transfer_id())?;
        Ok(())
    }
}

/// Errors that can occur during transaction processing.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Fail)]
#[repr(u8)]
pub enum Error {
    /// Wallet already exists.
    ///
    /// Can occur in [`CreateWallet`](self::CreateWallet).
    #[fail(display = "wallet already exists")]
    WalletExists = 0,

    /// The sender of a transfer is not registered.
    ///
    /// Can occur in [`Transfer`](self::Transfer).
    #[fail(display = "the sender of a transfer is not registered")]
    UnregisteredSender = 1,

    /// The receiver of a transfer is not registered.
    ///
    /// Can occur in [`Transfer`](self::Transfer).
    #[fail(display = "the receiver of a transfer is not registered")]
    UnregisteredReceiver = 2,

    /// The range proof for the sender’s sufficient account balance is incorrect.
    ///
    /// Can occur in [`Transfer`](self::Transfer).
    #[fail(display = "the range proof for the sender’s sufficient account balance is incorrect")]
    IncorrectProof = 3,

    /// There has been another outgoing transfer since the referenced point in time.
    ///
    /// Can occur in [`Transfer`](self::Transfer).
    #[fail(
        display = "there has been another outgoing transfer since the referenced point in time"
    )]
    OutdatedHistory = 4,

    /// Transfer refers to wallet history length exceeding real one.
    ///
    /// Can occur in [`Transfer`](self::Transfer).
    #[fail(display = "transfer refers to wallet history length exceeding real one")]
    InvalidHistoryRef = 5,

    /// An `Accept` transaction references an unknown transfer.
    ///
    /// Can occur in [`Accept`](self::Accept).
    #[fail(display = "an `Accept` transaction references an unknown transfer")]
    UnknownTransfer = 6,

    /// The author of an `Accept` transaction differs from the receiver of the referenced
    /// transfer.
    ///
    /// Can occur in [`Accept`](self::Accept).
    #[fail(
        display = "the author of an `Accept` transaction differs from the receiver \
                   of the referenced transfer"
    )]
    UnauthorizedAccept = 7,
}

impl From<Error> for ExecutionError {
    fn from(e: Error) -> Self {
        ExecutionError::new(e as u8)
    }
}
