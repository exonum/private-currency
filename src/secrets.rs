//! Utilities for managing the secret state of a wallet.

use exonum::crypto::{gen_keypair, CryptoHash, PublicKey, SecretKey};

use std::fmt;

use super::CONFIG;
use crypto::{enc, Commitment, Opening, SimpleRangeProof};
use storage::WalletInfo;
use transactions::{Accept, CreateWallet, Transfer};

lazy_static! {
    /// Opening to a minimum transfer amount.
    static ref MIN_TRANSFER_OPENING: Opening = Opening::with_no_blinding(CONFIG.min_transfer_amount);
}

encoding_struct! {
    /// Encrypted information embedded into transfers.
    struct EncryptedData {
        /// Cryptographic nonce for the `box` routine from `libsodium`.
        nonce: &[u8],
        /// Data encrypted with the `box` routine from `libsodium`.
        encrypted_data: &[u8],
    }
}

impl EncryptedData {
    /// Encrypts data based on sender's private encryption key
    /// and the receiver's public one.
    fn seal(message: &[u8], receiver: &enc::PublicKey, sender_sk: &enc::SecretKey) -> Self {
        let nonce = enc::gen_nonce();
        let encrypted_data = enc::seal(message, &nonce, receiver, sender_sk);

        EncryptedData::new(nonce.as_ref(), &encrypted_data)
    }

    /// Decrypts data based on sender's public encryption key
    /// and the receiver's secret one.
    fn open(&self, sender: &enc::PublicKey, receiver_sk: &enc::SecretKey) -> Option<Vec<u8>> {
        let nonce = enc::Nonce::from_slice(self.nonce())?;
        enc::open(self.encrypted_data(), &nonce, sender, receiver_sk).ok()
    }

    /// Decrypts data based on sender's private encryption key
    /// and the receiver's public one.
    // This is possible as `box` uses Diffie-Hellman key exchange to derive a shared secret
    // for encryption with a symmetric cipher. It's enough to know one secret key to restore
    // this shared secret.
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

/// Secret state of an account owner.
///
/// # Usage
///
/// `SecretState` can be used to create transactions originating from the wallet.
/// The state also should be updated based on the wallet history, which can be retrieved
/// with [HTTP API]. Each transaction in the history should be applied to the state
/// exactly once.
///
/// [HTTP API]: ::api::Api::wallet()
pub struct SecretState {
    encryption_sk: enc::SecretKey,
    signing_key: SecretKey,

    // We save verifying key for efficiency reasons.
    verifying_key: PublicKey,

    // This `Opening` is why `SecretState` is needed: we need to be able to open
    // the commitment to the wallet balance, which is stored in the blockchain,
    // in order to produce `Transfer`s and possibly for other tasks (such as proving
    // bounds on the balance to off-chain parties). If the opening is lost,
    // the wallet owner can no longer perform these tasks. Fortunately, with the given
    // design, it's always possible (and quite easy) to restore the opening from scratch
    // provided that the owner knows the secret key to the wallet; indeed, it's enough
    // to download wallet history anew and replay it.
    balance_opening: Opening,

    history_len: u64,
}

impl fmt::Debug for SecretState {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter
            .debug_struct("SecretState")
            .field("verifying_key", &self.verifying_key)
            .finish()
    }
}

/// Information about an incoming transfer successfully verified w.r.t. the `SecretState`
/// of the receiver's wallet.
#[derive(Debug)]
pub struct VerifiedTransfer {
    /// Opening for the transferred amount.
    pub opening: Opening,
    /// `Accept` transaction for the transfer.
    pub accept: Accept,
}

impl VerifiedTransfer {
    /// Gets the transferred amount in plaintext.
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
            history_len: 0,
        }
    }

    /// Gets the public key of the wallet (aka verifying Ed25519 for digital signatures).
    pub fn public_key(&self) -> &PublicKey {
        &self.verifying_key
    }

    /// Gets the current wallet balance.
    pub fn balance(&self) -> u64 {
        self.balance_opening.value
    }

    /// Produces a `CreateWallet` transaction for this wallet.
    pub fn create_wallet(&self) -> CreateWallet {
        CreateWallet::new(&self.verifying_key, &self.signing_key)
    }

    /// Produces a `Transfer` transaction from this wallet to the specified receiver.
    ///
    /// # Panics
    ///
    /// This method will panic if the transfer violates constraints imposed by the transaction
    /// logic of the service:
    ///
    /// - `amount` is lower than [`MIN_TRANSFER_AMOUNT`]
    /// - `receiver` is same as the sender
    /// - `rollback_delay` is not within acceptable range
    ///
    /// [`MIN_TRANSFER_AMOUNT`]: ::MIN_TRANSFER_AMOUNT
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
        assert_eq!(self.history_len, 0);
        debug_assert_eq!(self.balance_opening, Opening::with_no_blinding(0));
        self.balance_opening = Opening::with_no_blinding(CONFIG.initial_balance);
        self.history_len = 1;
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

        self.history_len += 1;
    }

    /// Rolls back a previously committed transfer.
    ///
    /// # Safety
    ///
    /// The transfer is assumed to be originating from the blockchain and rolled back
    /// according to the wallet history.
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
        self.history_len += 1;
    }

    /// Checks if this state corresponds to the supplied public info about a `Wallet`.
    pub fn corresponds_to(&self, wallet: &WalletInfo) -> bool {
        wallet.public_key == self.verifying_key && wallet.balance.verify(&self.balance_opening)
    }

    /// Produces a public info about the state.
    pub fn to_public(&self) -> WalletInfo {
        WalletInfo {
            public_key: self.verifying_key,
            balance: Commitment::from_opening(&self.balance_opening),
        }
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
        assert!(CONFIG.rollback_delay_bounds.start <= rollback_delay);
        assert!(rollback_delay < CONFIG.rollback_delay_bounds.end);
        assert!(amount >= CONFIG.min_transfer_amount);
        assert!(sender_secrets.balance_opening.value >= amount);
        assert_ne!(receiver, sender_secrets.public_key());

        let (committed_amount, opening) = Commitment::new(amount);
        let amount_proof = SimpleRangeProof::prove(&(&opening - &MIN_TRANSFER_OPENING))?;
        let remaining_balance = &sender_secrets.balance_opening - &opening;
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
            sender_secrets.history_len,
            committed_amount,
            amount_proof,
            sufficient_balance_proof,
            encrypted_data,
            &sender_secrets.signing_key,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exonum::blockchain::Transaction;

    fn gen_wallet(balance: u64) -> SecretState {
        let mut secrets = SecretState::new();
        secrets.balance_opening = Opening::with_no_blinding(balance);
        secrets
    }

    #[test]
    fn can_open_encrypted_data() {
        const MSG: &[u8] = b"hello";

        let sender = gen_wallet(100);
        let sender_pk = sender.to_public().encryption_key();
        let receiver = gen_wallet(100);
        let receiver_pk = receiver.to_public().encryption_key();

        let encrypted_data = EncryptedData::seal(MSG, &receiver_pk, &sender.encryption_sk);
        assert_eq!(
            encrypted_data.open(&sender_pk, &receiver.encryption_sk),
            Some(MSG.to_vec())
        );
        assert_eq!(
            encrypted_data.open_as_sender(&receiver_pk, &sender.encryption_sk),
            Some(MSG.to_vec())
        );
    }

    #[test]
    fn transfer_verifies() {
        let sender_sec = gen_wallet(100);
        let sender = sender_sec.to_public();
        let receiver_sec = gen_wallet(50);
        let receiver = receiver_sec.to_public();

        let transfer =
            Transfer::create(42, &receiver.public_key, 10, &sender_sec).expect("transfer");
        assert!(transfer.verify_stateless());
        assert!(transfer.verify_stateful(&sender.balance));

        let opening = transfer
            .encrypted_data()
            .open(&sender.encryption_key(), &receiver_sec.encryption_sk)
            .expect("decrypt");
        let opening = Opening::from_slice(&opening).expect("opening");
        assert_eq!(opening.value, 42);
        assert!(transfer.amount().verify(&opening));

        let opening = transfer
            .encrypted_data()
            .open_as_sender(&receiver.encryption_key(), &sender_sec.encryption_sk)
            .expect("decrypt");
        let opening = Opening::from_slice(&opening).expect("opening");
        assert_eq!(opening.value, 42);
        assert!(transfer.amount().verify(&opening));
    }

    #[test]
    fn transfer_with_small_amount_does_not_verify() {
        let sender_sec = gen_wallet(100);
        let (receiver, _) = gen_keypair();
        let (committed_amount, opening) = Commitment::new(0);

        // This intentionally deviates from the proper procedure - we don't subtract
        // `MIN_AMOUNT_OPENING` from the `opening`.
        let amount_proof = SimpleRangeProof::prove(&opening).expect("prove amount");

        let remaining_balance = &sender_sec.balance_opening - &opening;
        let sufficient_balance_proof =
            SimpleRangeProof::prove(&remaining_balance).expect("prove balance");
        let encrypted_data = EncryptedData::seal(
            &opening.to_bytes(),
            &enc::pk_from_ed25519(receiver),
            &sender_sec.encryption_sk,
        );

        let transfer = Transfer::new(
            &sender_sec.verifying_key,
            &receiver,
            10, // rollback delay
            1,  // history length
            committed_amount,
            amount_proof,
            sufficient_balance_proof,
            encrypted_data,
            &sender_sec.signing_key,
        );
        assert!(!transfer.verify());
    }
}
