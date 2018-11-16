use exonum::{
    blockchain::{ExecutionError, Transaction},
    crypto::{gen_keypair, CryptoHash, Hash, PublicKey, SecretKey},
    messages::Message,
    storage::Fork,
};

use std::fmt;

use super::{INITIAL_BALANCE, ROLLBACK_DELAY_BOUNDS, SERVICE_ID};
use crypto::{
    enc,
    proofs::{Commitment, Opening, SimpleRangeProof},
};
use storage::{maybe_transfer, Schema, Wallet};

encoding_struct! {
    struct EncryptedData {
        nonce: &[u8],
        encrypted_data: &[u8],
    }
}

impl EncryptedData {
    fn seal(message: &[u8], receiver: &enc::PublicKey, sender_sk: &enc::SecretKey) -> Self {
        let nonce = enc::gen_nonce();
        let encrypted_data = enc::seal(message, &nonce, receiver, sender_sk);

        EncryptedData::new(nonce.as_ref(), &encrypted_data)
    }

    fn open(&self, sender: &enc::PublicKey, receiver_sk: &enc::SecretKey) -> Option<Vec<u8>> {
        let nonce = enc::Nonce::from_slice(self.nonce())?;
        enc::open(self.encrypted_data(), &nonce, sender, receiver_sk).ok()
    }

    fn open_as_sender(
        &self,
        receiver: &enc::PublicKey,
        sender_sk: &enc::SecretKey,
    ) -> Option<Vec<u8>> {
        let nonce = enc::Nonce::from_slice(self.nonce())?;
        let precomputed_key = enc::precompute(receiver, sender_sk);
        enc::open_precomputed(self.encrypted_data(), &nonce, &precomputed_key).ok()
    }
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

/// Secret state of an account owner.
pub struct SecretState {
    encryption_sk: enc::SecretKey,
    signing_key: SecretKey,
    verifying_key: PublicKey,
    balance_opening: Opening,
}

impl fmt::Debug for SecretState {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter
            .debug_struct("SecretState")
            .field("verifying_key", &self.verifying_key)
            .finish()
    }
}

#[derive(Debug)]
pub struct VerifiedTransfer {
    pub opening: Opening,
    pub accept: Accept,
}

impl VerifiedTransfer {
    pub fn value(&self) -> u64 {
        self.opening.value
    }
}

impl SecretState {
    /// Creates an uninitialized state. The keypair for cryptographic operations
    /// is generated randomly.
    pub fn new() -> Self {
        let (verifying_key, signing_key) = gen_keypair();
        Self::from_keypair(verifying_key, signing_key)
    }

    /// Creates an uninitialized state from the specified Ed25519 keypair.
    pub fn from_keypair(verifying_key: PublicKey, signing_key: SecretKey) -> Self {
        let (_, encryption_sk) = enc::keypair_from_ed25519(verifying_key, signing_key.clone());
        SecretState {
            verifying_key,
            signing_key,
            encryption_sk,
            balance_opening: Opening::with_no_blinding(0),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.verifying_key
    }

    pub fn balance(&self) -> u64 {
        self.balance_opening.value
    }

    pub fn create_wallet(&self) -> CreateWallet {
        CreateWallet::new(&self.verifying_key, &self.signing_key)
    }

    pub fn create_transfer(
        &self,
        amount: u64,
        receiver: &PublicKey,
        rollback_delay: u32,
    ) -> Transfer {
        Transfer::create(amount, receiver, rollback_delay, self).expect("creating transfer failed")
    }

    /// Initializes the state.
    ///
    /// # Safety
    ///
    /// This method should be called after `CreateWallet` transaction is committed. It should
    /// only be called once.
    pub fn initialize(&mut self) {
        debug_assert_eq!(self.balance_opening, Opening::with_no_blinding(0));
        self.balance_opening = Opening::with_no_blinding(INITIAL_BALANCE);
    }

    /// Verifies an incoming transfer.
    ///
    /// # Return value
    ///
    /// Returns the decrypted opening for the transferred amount, or `None` if it cannot
    /// be decrypted from the transfer.
    pub fn verify_transfer(&self, transfer: &Transfer) -> Option<VerifiedTransfer> {
        if self.verifying_key == *transfer.to() {
            let sender = enc::pk_from_ed25519(*transfer.from());
            let opening = transfer
                .encrypted_data()
                .open(&sender, &self.encryption_sk)?;

            let accept = Accept::new(&self.verifying_key, &transfer.hash(), &self.signing_key);
            Some(VerifiedTransfer {
                opening: Opening::from_slice(&opening)?,
                accept,
            })
        } else {
            None
        }
    }

    /// Updates the state according to a `Transfer` transaction.
    ///
    /// # Safety
    ///
    /// The transfer is assumed to be previously [verified] or originating from self.
    /// It is also assumed to be sourced from the blockchain (i.e., verified according
    /// to the blockchain rules).
    ///
    /// [verified]: #method.verify
    pub fn transfer(&mut self, transfer: &Transfer) {
        if self.verifying_key == *transfer.from() {
            let receiver = enc::pk_from_ed25519(*transfer.to());
            let opening = transfer
                .encrypted_data()
                .open_as_sender(&receiver, &self.encryption_sk)
                .expect("cannot decrypt own message");
            let opening = Opening::from_slice(&opening).expect("cannot parse own message");
            self.balance_opening -= opening;
        } else if self.verifying_key == *transfer.to() {
            let sender = enc::pk_from_ed25519(*transfer.from());
            let opening = transfer
                .encrypted_data()
                .open(&sender, &self.encryption_sk)
                .expect("cannot decrypt message");
            let opening = Opening::from_slice(&opening).expect("cannot parse message");
            self.balance_opening += opening;
        } else {
            panic!("unrelated transfer");
        }
    }

    pub fn rollback(&mut self, transfer: &Transfer) {
        if self.verifying_key == *transfer.from() {
            let receiver = enc::pk_from_ed25519(*transfer.to());
            let opening = transfer
                .encrypted_data()
                .open_as_sender(&receiver, &self.encryption_sk)
                .expect("cannot decrypt own message");
            let opening = Opening::from_slice(&opening).expect("cannot parse own message");
            self.balance_opening += opening;
        } else {
            panic!("unrelated transfer");
        }
    }

    /// Checks if this state corresponds to the supplied public info about a `Wallet`.
    pub fn corresponds_to(&self, wallet: &Wallet) -> bool {
        *wallet.public_key() == self.verifying_key && wallet.balance().verify(&self.balance_opening)
    }

    /// Produces a public info about the state.
    pub fn to_public(&self) -> Wallet {
        Wallet::new(
            &self.verifying_key,
            Commitment::from_opening(&self.balance_opening),
        )
    }
}

impl Transfer {
    /// Creates a new transfer.
    fn create(
        amount: u64,
        receiver: &PublicKey,
        rollback_delay: u32,
        sender_secrets: &SecretState,
    ) -> Option<Self> {
        assert!(ROLLBACK_DELAY_BOUNDS.start <= rollback_delay);
        assert!(rollback_delay < ROLLBACK_DELAY_BOUNDS.end);
        assert!(sender_secrets.balance_opening.value >= amount);

        let (committed_amount, opening) = Commitment::new(amount);
        let amount_proof = SimpleRangeProof::prove(&opening)?;
        let remaining_balance = sender_secrets.balance_opening.clone() - opening.clone();
        let sufficient_balance_proof = SimpleRangeProof::prove(&remaining_balance)?;
        let encrypted_data = EncryptedData::seal(
            &opening.to_bytes(),
            &enc::pk_from_ed25519(*receiver),
            &sender_secrets.encryption_sk,
        );

        Some(Transfer::new(
            &sender_secrets.verifying_key,
            receiver,
            rollback_delay,
            committed_amount,
            amount_proof,
            sufficient_balance_proof,
            encrypted_data,
            &sender_secrets.signing_key,
        ))
    }

    /// Performs stateless verification of the transfer operation.
    fn verify(&self) -> bool {
        self.amount_proof().verify(&self.amount())
    }

    fn verify_stateful(&self, sender: &Wallet) -> bool {
        let remaining_balance = sender.balance() - self.amount();
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
        self.from() != self.to() && self.verify_signature(self.from()) && self.verify()
    }

    fn execute(&self, fork: &mut Fork) -> Result<(), ExecutionError> {
        let (sender, receiver) = {
            let schema = Schema::new(fork.as_ref());
            (schema.wallet(self.from()), schema.wallet(self.to()))
        };
        let sender = sender.ok_or(Error::UnregisteredSender)?;
        let receiver = receiver.ok_or(Error::UnregisteredReceiver)?;

        if !self.verify_stateful(&sender) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_wallet(balance: u64) -> (Wallet, SecretState) {
        let mut secrets = SecretState::new();
        secrets.balance_opening = Opening::with_no_blinding(balance);
        (secrets.to_public(), secrets)
    }

    #[test]
    fn can_open_encrypted_data() {
        const MSG: &[u8] = b"hello";

        let (
            sender,
            SecretState {
                encryption_sk: sender_sk,
                ..
            },
        ) = gen_wallet(100);
        let (
            receiver,
            SecretState {
                encryption_sk: receiver_sk,
                ..
            },
        ) = gen_wallet(100);

        let encrypted_data = EncryptedData::seal(MSG, &receiver.encryption_key(), &sender_sk);
        assert_eq!(
            encrypted_data.open(&sender.encryption_key(), &receiver_sk),
            Some(MSG.to_vec())
        );
        assert_eq!(
            encrypted_data.open_as_sender(&receiver.encryption_key(), &sender_sk),
            Some(MSG.to_vec())
        );
    }

    #[test]
    fn transfer_verifies() {
        let (sender, sender_secrets) = gen_wallet(100);
        let (receiver, receiver_secrets) = gen_wallet(50);

        let transfer =
            Transfer::create(42, &receiver.public_key(), 10, &sender_secrets).expect("transfer");
        assert!(transfer.verify());
        assert!(transfer.verify_stateful(&sender));

        let opening = transfer
            .encrypted_data()
            .open(&sender.encryption_key(), &receiver_secrets.encryption_sk)
            .expect("decrypt");
        let opening = Opening::from_slice(&opening).expect("opening");
        assert_eq!(opening.value, 42);
        assert!(transfer.amount().verify(&opening));

        let opening = transfer
            .encrypted_data()
            .open_as_sender(&receiver.encryption_key(), &sender_secrets.encryption_sk)
            .expect("decrypt");
        let opening = Opening::from_slice(&opening).expect("opening");
        assert_eq!(opening.value, 42);
        assert!(transfer.amount().verify(&opening));
    }
}
