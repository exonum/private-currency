use exonum::{
    blockchain::{ExecutionError, Transaction},
    crypto::{Hash, PublicKey},
    messages::Message,
    storage::Fork,
};

use super::{MIN_TRANSFER_AMOUNT, ROLLBACK_DELAY_BOUNDS, SERVICE_ID};
use crypto::proofs::{Commitment, SimpleRangeProof};
use secrets::EncryptedData;
use storage::{maybe_transfer, Schema, WalletInfo};

lazy_static! {
    static ref MIN_TRANSFER_COMMITMENT: Commitment =
        Commitment::with_no_blinding(MIN_TRANSFER_AMOUNT);
}

transactions! {
    pub CryptoTransactions {
        const SERVICE_ID = SERVICE_ID;

        /// Create a new wallet.
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

        /// Transfer funds from this wallet to the other wallet.
        ///
        /// # Notes
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
            /// Commitment to the transferred amount.
            amount: Commitment,
            /// Proof that `amount` is positive.
            amount_proof: SimpleRangeProof,
            /// Proof that the sender's balance is sufficient relative to `amount`.
            sufficient_balance_proof: SimpleRangeProof,
            /// Encryption of the opening for `amount`.
            encrypted_data: EncryptedData,
        }

        /// Accept a transfer.
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

    pub(crate) fn verify_stateful(&self, sender: &WalletInfo) -> bool {
        let remaining_balance = &sender.balance - &self.amount();
        self.sufficient_balance_proof().verify(&remaining_balance)
    }
}

impl Transaction for Transfer {
    fn verify(&self) -> bool {
        if ROLLBACK_DELAY_BOUNDS.start > self.rollback_delay()
            || ROLLBACK_DELAY_BOUNDS.end <= self.rollback_delay()
        {
            return false;
        }
        self.from() != self.to() && self.verify_signature(self.from()) && self.verify_stateless()
    }

    fn execute(&self, fork: &mut Fork) -> Result<(), ExecutionError> {
        let (sender, receiver) = {
            let schema = Schema::new(fork.as_ref());
            (schema.wallet(self.from()), schema.wallet(self.to()))
        };
        let sender = sender.ok_or(Error::UnregisteredSender)?;
        let receiver = receiver.ok_or(Error::UnregisteredReceiver)?;

        if !self.verify_stateful(&sender.info()) {
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

#[repr(u8)]
pub enum Error {
    WalletExists = 0,
    InvalidEncryptionKey = 1,
    UnregisteredSender = 3,
    UnregisteredReceiver = 4,
    IncorrectProof = 5,
    UnknownTransfer = 6,
    UnauthorizedAccept = 7,
}

impl From<Error> for ExecutionError {
    fn from(e: Error) -> Self {
        ExecutionError::new(e as u8)
    }
}
