use exonum::crypto::{gen_keypair, CryptoHash, PublicKey, SecretKey};

use std::fmt;

use super::{INITIAL_BALANCE, MIN_TRANSFER_AMOUNT, ROLLBACK_DELAY_BOUNDS};
use crypto::{
    enc,
    proofs::{Commitment, Opening, SimpleRangeProof},
};
use storage::WalletInfo;
use transactions::{Accept, CreateWallet, Transfer};

lazy_static! {
    static ref MIN_TRANSFER_OPENING: Opening = Opening::with_no_blinding(MIN_TRANSFER_AMOUNT);
}

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
        assert!(ROLLBACK_DELAY_BOUNDS.start <= rollback_delay);
        assert!(rollback_delay < ROLLBACK_DELAY_BOUNDS.end);
        assert!(amount >= MIN_TRANSFER_AMOUNT);
        assert!(sender_secrets.balance_opening.value >= amount);

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
        assert!(transfer.verify_stateful(&sender));

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
            10,
            committed_amount,
            amount_proof,
            sufficient_balance_proof,
            encrypted_data,
            &sender_sec.signing_key,
        );
        assert!(!transfer.verify());
    }
}
